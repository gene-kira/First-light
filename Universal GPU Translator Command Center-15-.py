#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Universal GPU Translator Command Center
Next-Level, Game-Aware, Predictive GPU Governor + RL + Temporal AI + Game Memory + Swarm
Distributed Rendering (VRAM Farm) + Borg VRAM Network + Board Neural Network (Out-of-the-Box Optimizer)

- Distributed VRAM Farm: offload rendering to other swarm nodes when local VRAM is insufficient.
- Borg VRAM Network: collective shortcut discovery for faster, more efficient video memory usage across the swarm.
- Board Neural Network: "out-of-the-box thinking" layer that searches for indirect, creative optimization strategies
  (like moving the copier under the thermostat or shimming the starter) for VRAM, load, and constraints.
"""

import os
import sys
import subprocess
import importlib
import json
import time
import traceback
import math
from collections import deque

APP_VERSION = "2.4.0-UGTC-GOVERNOR-PREDICTIVE-RL-TEMPORAL-GAME-MEM-V3-SWARM-DR-BORG-BOARD"
AUTOLOADER_VERSION = "1.0-ORIGINAL"
LOGFILE = os.path.join(os.getcwd(), "gpu_translator.log")
PROFILE_PATH = os.path.join(os.getcwd(), "gpu_translation_profiles.json")
SETTINGS_PATH = os.path.join(os.getcwd(), "gpu_translator_settings.json")
PLUGIN_DIR = os.path.join(os.getcwd(), "plugins")
AI_DATASET_PATH = os.path.join(os.getcwd(), "gpu_ai_dataset.json")
GAME_MEMORY_PATH = os.path.join(os.getcwd(), "gpu_game_memory.json")
SWARM_STATE_PATH = os.path.join(os.getcwd(), "gpu_swarm_state.json")
SWARM_RENDER_TASKS_PATH = os.path.join(os.getcwd(), "gpu_swarm_render_tasks.json")
BORG_VRAM_PATH = os.path.join(os.getcwd(), "gpu_borg_vram_shortcuts.json")
BOARD_NETWORK_PATH = os.path.join(os.getcwd(), "gpu_board_network_ideas.json")

# ======================================================================
# Logging
# ======================================================================

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ======================================================================
# ORIGINAL-STYLE AUTOLOADER (RESTORED)
# ======================================================================

REQUIRED_LIBRARIES = {
    "PySide6": "PySide6",
    "GPUtil": "gputil",
    "psutil": "psutil",
    "numpy": "numpy",
    "torch": "torch",
    "pynvml": "pynvml",
    "jsonschema": "jsonschema",
    "requests": "requests",
}

def install_package(pkg_name):
    log(f"[AUTOLOADER] Installing missing package: {pkg_name}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
        log(f"[AUTOLOADER] Successfully installed: {pkg_name}")
    except Exception as e:
        log(f"[AUTOLOADER] FAILED to install {pkg_name}: {e}")

def check_and_import(lib, pkg):
    try:
        return importlib.import_module(lib)
    except ImportError:
        install_package(pkg)
        try:
            return importlib.import_module(lib)
        except ImportError as e:
            log(f"[AUTOLOADER] FINAL FAILURE: Could not import {lib}: {e}")
            return None

def autoload():
    log(f"[AUTOLOADER] Autoloader v{AUTOLOADER_VERSION} starting...")
    loaded_modules = {}
    for lib, pkg in REQUIRED_LIBRARIES.items():
        log(f"[AUTOLOADER] Checking library: {lib}")
        module = check_and_import(lib, pkg)
        loaded_modules[lib] = module
    log("[AUTOLOADER] Autoloader finished.")
    return loaded_modules

MODULES = autoload()

PySide6 = MODULES.get("PySide6")
GPUtil = MODULES.get("GPUtil")
psutil = MODULES.get("psutil")
np = MODULES.get("numpy")
torch = MODULES.get("torch")
pynvml = MODULES.get("pynvml")
jsonschema = MODULES.get("jsonschema")
requests = MODULES.get("requests")

if PySide6 is None:
    log("[FATAL] PySide6 could not be loaded. Install with: pip install PySide6")
    sys.exit(1)

from PySide6 import QtWidgets, QtCore, QtGui

# ======================================================================
# Plugin System v2 (Predictive + Swarm + Distributed Rendering + Borg + Board Hooks)
# ======================================================================

class PluginManager:
    def __init__(self, plugin_dir=PLUGIN_DIR):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugin_dir):
            os.makedirs(self.plugin_dir, exist_ok=True)
            log(f"[PluginManager] Created plugin directory at {self.plugin_dir}")
            return
        for fname in os.listdir(self.plugin_dir):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.plugin_dir, fname)
            mod_name = f"plugin_{os.path.splitext(fname)[0]}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                module = importlib.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.plugins.append(module)
                log(f"[PluginManager] Loaded plugin: {fname}")
            except Exception as e:
                log(f"[PluginManager] Failed to load plugin {fname}: {e}")
                log(traceback.format_exc())

    def _call_hook(self, hook_name, *args, **kwargs):
        for plugin in self.plugins:
            func = getattr(plugin, hook_name, None)
            if callable(func):
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    log(f"[PluginManager] Plugin hook {hook_name} failed: {e}")
                    log(traceback.format_exc())

    # v1 hooks
    def on_gpu_detected(self, gpus):
        self._call_hook("on_gpu_detected", gpus)

    def on_profile_built(self, profile_dict):
        self._call_hook("on_profile_built", profile_dict)

    def on_benchmark_completed(self, profile_dict):
        self._call_hook("on_benchmark_completed", profile_dict)

    def on_game_detected(self, game_info, profile_dict):
        self._call_hook("on_game_detected", game_info, profile_dict)

    def on_policy_applied(self, policy_dict):
        self._call_hook("on_policy_applied", policy_dict)

    # v2 predictive hooks
    def on_gpu_telemetry(self, telemetry_snapshot):
        self._call_hook("on_gpu_telemetry", telemetry_snapshot)

    def on_predictive_risk(self, risk_info):
        self._call_hook("on_predictive_risk", risk_info)

    def on_rl_decision(self, decision_info):
        self._call_hook("on_rl_decision", decision_info)

    def on_game_memory_update(self, game_key, memory_entry):
        self._call_hook("on_game_memory_update", game_key, memory_entry)

    # swarm hooks
    def on_swarm_state_updated(self, swarm_state):
        self._call_hook("on_swarm_state_updated", swarm_state)

    def on_swarm_policy_decision(self, decision_info):
        self._call_hook("on_swarm_policy_decision", decision_info)

    # distributed rendering hooks
    def on_render_task_created(self, task):
        self._call_hook("on_render_task_created", task)

    def on_render_task_assigned(self, task, node_id):
        self._call_hook("on_render_task_assigned", task, node_id)

    def on_render_result_received(self, result):
        self._call_hook("on_render_result_received", result)

    # Borg VRAM network hooks
    def on_borg_shortcut_discovered(self, shortcut):
        self._call_hook("on_borg_shortcut_discovered", shortcut)

    def on_borg_shortcut_applied(self, shortcut, context):
        self._call_hook("on_borg_shortcut_applied", shortcut, context)

    # Board neural network hooks
    def on_board_idea_generated(self, idea):
        self._call_hook("on_board_idea_generated", idea)

    def on_board_idea_applied(self, idea, context):
        self._call_hook("on_board_idea_applied", idea, context)

# ======================================================================
# GPU + Driver Detection
# ======================================================================

class GPUInfo:
    def __init__(self, name="", id_str="", memory_total_mb=0, load=0.0,
                 driver_version="", vendor="unknown", temperature=None,
                 cuda_capability=None):
        self.name = name
        self.id_str = id_str
        self.memory_total_mb = memory_total_mb
        self.load = load
        self.driver_version = driver_version
        self.vendor = vendor
        self.temperature = temperature
        self.cuda_capability = cuda_capability

    def to_dict(self):
        return {
            "name": self.name,
            "id": self.id_str,
            "memory_total_mb": self.memory_total_mb,
            "load": self.load,
            "driver_version": self.driver_version,
            "vendor": self.vendor,
            "temperature": self.temperature,
            "cuda_capability": self.cuda_capability,
        }

class GPUDetector:
    def __init__(self):
        self.gpus = []
        self.initialized_nvml = False
        self._init_nvml()

    def _init_nvml(self):
        if pynvml is None:
            log("[GPUDetector] pynvml not available, NV-specific info disabled.")
            return
        try:
            pynvml.nvmlInit()
            self.initialized_nvml = True
            log("[GPUDetector] NVML initialized.")
        except Exception as e:
            log(f"[GPUDetector] NVML init failed: {e}")
            self.initialized_nvml = False

    def _get_nvml_info(self, index):
        if not self.initialized_nvml:
            return None, None, None
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(index)
            mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
            driver = pynvml.nvmlSystemGetDriverVersion()
            temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
            return mem, driver, temp
        except Exception as e:
            log(f"[GPUDetector] NVML info failed for index {index}: {e}")
            return None, None, None

    def detect(self):
        self.gpus = []
        try:
            if GPUtil is None:
                log("[GPUDetector] GPUtil not available, no GPU list.")
                return self.gpus

            devices = GPUtil.getGPUs()
            for idx, d in enumerate(devices):
                mem_info, driver_version, temp = self._get_nvml_info(idx)
                if mem_info:
                    mem_total_mb = int(mem_info.total / (1024 * 1024))
                else:
                    mem_total_mb = int(getattr(d, "memoryTotal", 0))

                vendor = "nvidia" if "NVIDIA" in d.name.upper() else "unknown"

                cuda_cap = None
                if torch is not None and torch.cuda.is_available():
                    try:
                        cap = torch.cuda.get_device_capability(idx)
                        cuda_cap = f"{cap[0]}.{cap[1]}"
                    except Exception:
                        cuda_cap = None

                gpu = GPUInfo(
                    name=d.name,
                    id_str=str(d.id),
                    memory_total_mb=mem_total_mb,
                    load=float(d.load) * 100.0,
                    driver_version=driver_version if driver_version else "unknown",
                    vendor=vendor,
                    temperature=temp,
                    cuda_capability=cuda_cap,
                )
                self.gpus.append(gpu)

            log(f"[GPUDetector] Detected {len(self.gpus)} GPU(s).")
        except Exception as e:
            log(f"[GPUDetector] Detection error: {e}")
            log(traceback.format_exc())
        return self.gpus

class DriverInfo:
    def __init__(self, name="", version="", api_support=None):
        self.name = name
        self.version = version
        self.api_support = api_support or {
            "DirectX": False,
            "Vulkan": False,
            "OpenGL": False,
            "CUDA": False,
        }

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "api_support": self.api_support,
        }

class DriverDetector:
    def __init__(self, gpu_detector: GPUDetector):
        self.gpu_detector = gpu_detector
        self.drivers = []

    def detect(self):
        self.drivers = []
        try:
            gpus = self.gpu_detector.detect()
            for gpu in gpus:
                api_support = {
                    "DirectX": True,
                    "Vulkan": True,
                    "OpenGL": True,
                    "CUDA": gpu.cuda_capability is not None,
                }
                driver = DriverInfo(
                    name=f"{gpu.vendor}_driver",
                    version=gpu.driver_version,
                    api_support=api_support,
                )
                self.drivers.append(driver)
            log(f"[DriverDetector] Detected {len(self.drivers)} driver(s) (inferred).")
        except Exception as e:
            log(f"[DriverDetector] Detection error: {e}")
            log(traceback.format_exc())
        return self.drivers

# ======================================================================
# Swarm Coordinator & Node State
# ======================================================================

class SwarmCoordinator:
    def __init__(self, node_id: str, plugin_manager: PluginManager, path=SWARM_STATE_PATH):
        self.node_id = node_id
        self.plugin_manager = plugin_manager
        self.path = path
        self.state = self._load_state()

    def _load_state(self):
        if not os.path.exists(self.path):
            return {"nodes": {}}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "nodes" in data:
                log("[SwarmCoordinator] Loaded swarm state.")
                return data
            return {"nodes": {}}
        except Exception as e:
            log(f"[SwarmCoordinator] Failed to load swarm state: {e}")
            log(traceback.format_exc())
            return {"nodes": {}}

    def _save_state(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            log("[SwarmCoordinator] Swarm state saved.")
        except Exception as e:
            log(f"[SwarmCoordinator] Failed to save swarm state: {e}")
            log(traceback.format_exc())

    def update_node_state(self, gpu_info: GPUInfo, risk_info: dict, mode: str, game_exe: str | None):
        node_entry = {
            "node_id": self.node_id,
            "ts": time.time(),
            "gpu_name": gpu_info.name,
            "gpu_mem_mb": gpu_info.memory_total_mb,
            "gpu_load": gpu_info.load,
            "gpu_temp": float(gpu_info.temperature or 0.0),
            "risk": float(risk_info.get("risk", 0.0)),
            "mode": mode,
            "game_exe": game_exe or "",
        }
        self.state["nodes"][self.node_id] = node_entry
        self._save_state()
        self.plugin_manager.on_swarm_state_updated(self.state)

    def compute_global_aggressiveness(self, base_aggr: int):
        nodes = list(self.state["nodes"].values())
        if not nodes:
            return base_aggr

        avg_risk = sum(n.get("risk", 0.0) for n in nodes) / len(nodes)
        avg_load = sum(n.get("gpu_load", 0.0) for n in nodes) / len(nodes)

        if avg_risk > 0.8 or avg_load > 90.0:
            delta = -1
        elif avg_risk < 0.3 and avg_load < 60.0:
            delta = +1
        else:
            delta = 0

        new_aggr = max(0, min(3, base_aggr + delta))
        decision = {
            "base_aggr": base_aggr,
            "new_aggr": new_aggr,
            "avg_risk": avg_risk,
            "avg_load": avg_load,
            "nodes_count": len(nodes),
        }
        self.plugin_manager.on_swarm_policy_decision(decision)
        log(f"[SwarmCoordinator] Global aggressiveness decision: {decision}")
        return new_aggr

# ======================================================================
# Distributed Rendering / VRAM Farm
# ======================================================================

class DistributedRenderManager:
    """
    Conceptual distributed rendering manager:
    - When local VRAM is insufficient for a game, create render tasks.
    - Other nodes in the swarm can pick up tasks and return results.
    - This is modeled as JSON-based task sharing; actual GPU frame streaming
      would require a dedicated network protocol and integration with the game.
    """

    def __init__(self, node_id: str, plugin_manager: PluginManager, path=SWARM_RENDER_TASKS_PATH):
        self.node_id = node_id
        self.plugin_manager = plugin_manager
        self.path = path
        self.tasks = self._load_tasks()

    def _load_tasks(self):
        if not os.path.exists(self.path):
            return {"tasks": [], "results": []}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                log("[DistributedRenderManager] Loaded render tasks.")
                return data
            return {"tasks": [], "results": []}
        except Exception as e:
            log(f"[DistributedRenderManager] Failed to load render tasks: {e}")
            log(traceback.format_exc())
            return {"tasks": [], "results": []}

    def _save_tasks(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.tasks, f, indent=2)
            log("[DistributedRenderManager] Render tasks saved.")
        except Exception as e:
            log(f"[DistributedRenderManager] Failed to save render tasks: {e}")
            log(traceback.format_exc())

    def create_render_task(self, game_exe: str, required_vram_mb: int, local_vram_mb: int):
        deficit = max(0, required_vram_mb - local_vram_mb)
        if deficit <= 0:
            return None

        task = {
            "id": f"task-{int(time.time() * 1000)}",
            "created_by": self.node_id,
            "game_exe": game_exe,
            "required_vram_mb": required_vram_mb,
            "local_vram_mb": local_vram_mb,
            "deficit_mb": deficit,
            "status": "pending",
            "assigned_to": None,
            "created_at": time.time(),
        }
        self.tasks["tasks"].append(task)
        self._save_tasks()
        self.plugin_manager.on_render_task_created(task)
        log(f"[DistributedRenderManager] Created render task for {game_exe}, deficit={deficit} MB")
        return task

    def assign_tasks_to_node(self, node_id: str, available_vram_mb: int):
        assigned = []
        for task in self.tasks["tasks"]:
            if task["status"] == "pending" and task["deficit_mb"] <= available_vram_mb:
                task["status"] = "assigned"
                task["assigned_to"] = node_id
                assigned.append(task)
                self.plugin_manager.on_render_task_assigned(task, node_id)
        if assigned:
            self._save_tasks()
        return assigned

    def submit_render_result(self, task_id: str, node_id: str, quality_hint: str = "high"):
        result = {
            "task_id": task_id,
            "node_id": node_id,
            "quality_hint": quality_hint,
            "ts": time.time(),
        }
        self.tasks["results"].append(result)
        for task in self.tasks["tasks"]:
            if task["id"] == task_id:
                task["status"] = "completed"
        self._save_tasks()
        self.plugin_manager.on_render_result_received(result)
        log(f"[DistributedRenderManager] Render result submitted for {task_id} by {node_id}")
        return result

    def get_results_for_game(self, game_exe: str):
        results = []
        for r in self.tasks["results"]:
            for t in self.tasks["tasks"]:
                if t["id"] == r["task_id"] and t["game_exe"] == game_exe:
                    results.append(r)
        return results

# ======================================================================
# Borg VRAM Network – Shortcut Discovery Layer
# ======================================================================

class BorgVramNetwork:
    """
    Borg-style VRAM network:
    - Observes render tasks, results, and game memory.
    - Learns "shortcuts" (patterns) where VRAM usage can be reduced or reused.
    - Exposes hints that can be applied to future tasks or policies.
    This is conceptual: we model shortcuts as metadata about reuse/compression strategies.
    """

    def __init__(self, plugin_manager: PluginManager, path=BORG_VRAM_PATH):
        self.plugin_manager = plugin_manager
        self.path = path
        self.shortcuts = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return {"shortcuts": []}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "shortcuts" in data:
                log("[BorgVramNetwork] Loaded VRAM shortcuts.")
                return data
            return {"shortcuts": []}
        except Exception as e:
            log(f"[BorgVramNetwork] Failed to load VRAM shortcuts: {e}")
            log(traceback.format_exc())
            return {"shortcuts": []}

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.shortcuts, f, indent=2)
            log("[BorgVramNetwork] VRAM shortcuts saved.")
        except Exception as e:
            log(f"[BorgVramNetwork] Failed to save VRAM shortcuts: {e}")
            log(traceback.format_exc())

    def observe_render_activity(self, render_manager: DistributedRenderManager, game_memory):
        tasks = render_manager.tasks.get("tasks", [])
        results = render_manager.tasks.get("results", [])
        by_game = {}

        for t in tasks:
            g = t["game_exe"]
            by_game.setdefault(g, {"tasks": [], "results": []})
            by_game[g]["tasks"].append(t)
        for r in results:
            for t in tasks:
                if t["id"] == r["task_id"]:
                    g = t["game_exe"]
                    by_game.setdefault(g, {"tasks": [], "results": []})
                    by_game[g]["results"].append(r)

        for game_exe, grp in by_game.items():
            mem_entry = game_memory.get(game_exe)
            if not mem_entry:
                continue

            avg_load = mem_entry.get("avg_gpu_load", 0.0)
            avg_temp = mem_entry.get("avg_gpu_temp", 0.0)
            deficit_tasks = [t for t in grp["tasks"] if t["deficit_mb"] > 0]
            completed_results = grp["results"]

            if not deficit_tasks:
                continue

            if avg_load < 85.0 and avg_temp < 80.0:
                shortcut = {
                    "id": f"shortcut-compress-{game_exe}-{int(time.time())}",
                    "game_exe": game_exe,
                    "type": "compression_reuse",
                    "hint": "Use texture compression / reuse cached tiles for this game.",
                    "avg_load": avg_load,
                    "avg_temp": avg_temp,
                    "deficit_tasks": len(deficit_tasks),
                }
                self.shortcuts["shortcuts"].append(shortcut)
                self._save()
                self.plugin_manager.on_borg_shortcut_discovered(shortcut)
                log(f"[BorgVramNetwork] Discovered compression shortcut for {game_exe}")

            nodes = {r["node_id"] for r in completed_results}
            if len(nodes) >= 2 and len(completed_results) >= 2:
                shortcut = {
                    "id": f"shortcut-tiling-{game_exe}-{int(time.time())}",
                    "game_exe": game_exe,
                    "type": "multi_node_tiling",
                    "hint": "Distribute frame tiles across multiple nodes for faster completion.",
                    "nodes": list(nodes),
                    "results_count": len(completed_results),
                }
                self.shortcuts["shortcuts"].append(shortcut)
                self._save()
                self.plugin_manager.on_borg_shortcut_discovered(shortcut)
                log(f"[BorgVramNetwork] Discovered tiling shortcut for {game_exe}")

    def get_shortcuts_for_game(self, game_exe: str):
        return [
            s for s in self.shortcuts.get("shortcuts", [])
            if s.get("game_exe") == game_exe
        ]

    def apply_shortcuts_to_task(self, game_exe: str, task: dict):
        shortcuts = self.get_shortcuts_for_game(game_exe)
        if not shortcuts:
            return task

        task.setdefault("borg_hints", [])
        for s in shortcuts:
            task["borg_hints"].append(s["hint"])
            self.plugin_manager.on_borg_shortcut_applied(s, {"task_id": task["id"], "game_exe": game_exe})
        log(f"[BorgVramNetwork] Applied {len(shortcuts)} shortcut(s) to task {task['id']} for {game_exe}")
        return task

# ======================================================================
# Board Neural Network – Out-of-the-Box Optimization Layer
# ======================================================================

class BoardNeuralNetwork:
    """
    Board-style neural network:
    - Inspired by "move the copier under the thermostat" and "shim the starter with a washer".
    - Looks for indirect, creative strategies when direct resources are insufficient.
    - Works on high-level constraints: VRAM deficit, high load, temperature, swarm capacity.
    - Produces "ideas" that suggest unconventional tweaks (e.g., resolution scaling, UI offload,
      pre-warming caches, shifting non-critical tasks to other nodes, etc.).
    """

    def __init__(self, plugin_manager: PluginManager, path=BOARD_NETWORK_PATH):
        self.plugin_manager = plugin_manager
        self.path = path
        self.ideas = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return {"ideas": []}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "ideas" in data:
                log("[BoardNeuralNetwork] Loaded board ideas.")
                return data
            return {"ideas": []}
        except Exception as e:
            log(f"[BoardNeuralNetwork] Failed to load board ideas: {e}")
            log(traceback.format_exc())
            return {"ideas": []}

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.ideas, f, indent=2)
            log("[BoardNeuralNetwork] Board ideas saved.")
        except Exception as e:
            log(f"[BoardNeuralNetwork] Failed to save board ideas: {e}")
            log(traceback.format_exc())

    def _new_idea(self, game_exe: str, category: str, description: str, context: dict):
        idea = {
            "id": f"idea-{category}-{game_exe}-{int(time.time())}",
            "game_exe": game_exe,
            "category": category,
            "description": description,
            "context": context,
            "ts": time.time(),
        }
        self.ideas["ideas"].append(idea)
        self._save()
        self.plugin_manager.on_board_idea_generated(idea)
        log(f"[BoardNeuralNetwork] Generated idea for {game_exe}: {category} -> {description}")
        return idea

    def generate_out_of_box_ideas(self, game_exe: str, gpu: GPUInfo, risk_info: dict,
                                  render_manager: DistributedRenderManager, borg_network: BorgVramNetwork,
                                  game_memory):
        """
        Look at constraints and propose creative strategies:
        - If VRAM deficit exists: suggest indirect VRAM relief (UI offload, texture streaming, etc.).
        - If temp is high but load moderate: suggest airflow-friendly scheduling or frame pacing.
        - If swarm has idle nodes: suggest moving non-critical tasks to them.
        """
        mem_entry = game_memory.get(game_exe)
        avg_load = mem_entry.get("avg_gpu_load", gpu.load) if mem_entry else gpu.load
        avg_temp = mem_entry.get("avg_gpu_temp", float(gpu.temperature or 0.0)) if mem_entry else float(gpu.temperature or 0.0)
        risk = float(risk_info.get("risk", 0.0))

        tasks = render_manager.tasks.get("tasks", [])
        deficit_tasks = [t for t in tasks if t["game_exe"] == game_exe and t["deficit_mb"] > 0]

        ideas = []

        # Idea 1: "Washer on the starter" – small offset tweak
        if deficit_tasks:
            context = {
                "deficit_tasks": len(deficit_tasks),
                "avg_deficit_mb": sum(t["deficit_mb"] for t in deficit_tasks) / len(deficit_tasks),
            }
            desc = (
                "Apply small VRAM offset strategies: move HUD/UI to lower-res textures, "
                "pre-stream non-critical assets, and reuse shadow maps to reduce peak VRAM."
            )
            ideas.append(self._new_idea(game_exe, "vrm_offset", desc, context))

        # Idea 2: "Copier under thermostat" – indirect trigger
        if avg_temp < 80.0 and risk > 0.5 and avg_load < 85.0:
            context = {
                "avg_temp": avg_temp,
                "risk": risk,
                "avg_load": avg_load,
            }
            desc = (
                "Use indirect load triggers: slightly increase frame pacing or pre-warm caches "
                "during low-load moments to avoid sudden spikes that cause thermal/risk jumps."
            )
            ideas.append(self._new_idea(game_exe, "indirect_trigger", desc, context))

        # Idea 3: "Move work to swarm" – offload non-critical tasks
        results = render_manager.get_results_for_game(game_exe)
        if results:
            nodes = {r["node_id"] for r in results}
            if len(nodes) >= 1:
                context = {
                    "nodes": list(nodes),
                    "results_count": len(results),
                }
                desc = (
                    "Offload non-critical post-processing (bloom, SSAO, color grading) to swarm nodes "
                    "and keep local GPU focused on core geometry and physics."
                )
                ideas.append(self._new_idea(game_exe, "swarm_offload", desc, context))

        # Idea 4: "Shortcut synergy" – combine Borg hints with board ideas
        borg_shortcuts = borg_network.get_shortcuts_for_game(game_exe)
        if borg_shortcuts:
            context = {
                "borg_shortcuts": [s["type"] for s in borg_shortcuts],
            }
            desc = (
                "Combine Borg compression/tiling shortcuts with resolution scaling in menus and "
                "background scenes to free VRAM for combat-heavy moments."
            )
            ideas.append(self._new_idea(game_exe, "synergy", desc, context))

        return ideas

    def get_ideas_for_game(self, game_exe: str):
        return [
            i for i in self.ideas.get("ideas", [])
            if i.get("game_exe") == game_exe
        ]

    def apply_ideas_to_task(self, game_exe: str, task: dict):
        """
        Conceptual application: annotate tasks with board ideas.
        """
        ideas = self.get_ideas_for_game(game_exe)
        if not ideas:
            return task

        task.setdefault("board_ideas", [])
        for idea in ideas:
            task["board_ideas"].append(idea["description"])
            self.plugin_manager.on_board_idea_applied(idea, {"task_id": task["id"], "game_exe": game_exe})
        log(f"[BoardNeuralNetwork] Applied {len(ideas)} idea(s) to task {task['id']} for {game_exe}")
        return task

# ======================================================================
# Predictive GPU Telemetry Engine
# ======================================================================

class PredictiveTelemetryEngine:
    def __init__(self, plugin_manager: PluginManager, window_size=64):
        self.plugin_manager = plugin_manager
        self.window_size = window_size
        self.samples = deque(maxlen=window_size)

    def sample(self, gpu_info: GPUInfo):
        if gpu_info is None:
            return
        entry = {
            "ts": time.time(),
            "temp": float(gpu_info.temperature or 0.0),
            "load": float(gpu_info.load or 0.0),
            "vram_total_mb": float(gpu_info.memory_total_mb or 0.0),
        }
        self.samples.append(entry)
        self.plugin_manager.on_gpu_telemetry(entry)

    def _slope(self, key):
        if len(self.samples) < 2:
            return 0.0
        xs = list(self.samples)
        v0 = xs[0][key]
        v1 = xs[-1][key]
        dt = max(xs[-1]["ts"] - xs[0]["ts"], 1e-3)
        return (v1 - v0) / dt

    def compute_risk(self, horizon_sec=10.0):
        if not self.samples:
            return {"risk": 0.0, "projected_temp": 0.0, "projected_load": 0.0}

        last = self.samples[-1]
        temp = last["temp"]
        load = last["load"]

        temp_slope = self._slope("temp")
        load_slope = self._slope("load")

        projected_temp = temp + temp_slope * horizon_sec
        projected_load = load + load_slope * horizon_sec

        temp_risk = max(0.0, min(1.0, (projected_temp - 65.0) / 25.0))
        load_risk = max(0.0, min(1.0, (projected_load - 70.0) / 30.0))

        risk = 0.6 * temp_risk + 0.4 * load_risk

        info = {
            "risk": risk,
            "projected_temp": projected_temp,
            "projected_load": projected_load,
            "temp_slope": temp_slope,
            "load_slope": load_slope,
        }
        self.plugin_manager.on_predictive_risk(info)
        return info

# ======================================================================
# AI Translation Engine (Temporal Model + RL)
# ======================================================================

class TranslationProfile:
    def __init__(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced",
                 ai_score=0.0, heuristic_score=0.0, benchmark_score=0.0,
                 capabilities=None, game_exe=None, policy=None,
                 aggressiveness=1):
        self.gpu = gpu
        self.driver = driver
        self.mode = mode
        self.created_at = time.time()
        self.ai_score = ai_score
        self.heuristic_score = heuristic_score
        self.benchmark_score = benchmark_score
        self.capabilities = capabilities or {}
        self.game_exe = game_exe
        self.policy = policy or {
            "type": "auto",
            "aggressiveness": aggressiveness,
        }

    def to_dict(self):
        return {
            "gpu": self.gpu.to_dict() if self.gpu else None,
            "driver": self.driver.to_dict() if self.driver else None,
            "mode": self.mode,
            "created_at": self.created_at,
            "ai_score": self.ai_score,
            "heuristic_score": self.heuristic_score,
            "benchmark_score": self.benchmark_score,
            "capabilities": self.capabilities,
            "game_exe": self.game_exe,
            "policy": self.policy,
        }

class TemporalTranslatorNet(torch.nn.Module if torch is not None else object):
    def __init__(self, input_dim=12, hidden_dim=32):
        if torch is None:
            return
        super().__init__()
        self.lstm = torch.nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = torch.nn.Linear(hidden_dim, 1)
        self.act = torch.nn.ReLU()

    def forward(self, x_seq):
        out, _ = self.lstm(x_seq)
        last = out[:, -1, :]
        x = self.act(self.fc(last))
        return x

class RLAgent:
    def __init__(self):
        self.actions = ["soft", "balanced", "aggressive"]
        self.q_values = {}
        self.counts = {}
        self.total_decisions = 0

    def _ensure_state(self, state_key):
        if state_key not in self.q_values:
            self.q_values[state_key] = {a: 0.0 for a in self.actions}
            self.counts[state_key] = {a: 0 for a in self.actions}
        return self.q_values[state_key], self.counts[state_key]

    def choose(self, state_key, risk):
        q, counts = self._ensure_state(state_key)
        self.total_decisions += 1
        exploration = max(0.05, min(0.25, 0.25 / math.sqrt(1 + self.total_decisions / 20.0)))

        if risk >= 0.8:
            action = "soft"
        elif risk <= 0.3:
            action = "aggressive"
        else:
            if np is not None and np.random.rand() < exploration:
                action = np.random.choice(self.actions)
            else:
                action = max(self.actions, key=lambda a: q[a])
        return action

    def update(self, state_key, action, reward):
        q, counts = self._ensure_state(state_key)
        old = q[action]
        alpha = 0.2
        q[action] = old + alpha * (reward - old)
        counts[action] += 1

class AITranslatorEngine:
    def __init__(self, plugin_manager: PluginManager, telemetry_engine: PredictiveTelemetryEngine, swarm: SwarmCoordinator):
        self.current_profile = None
        self.model = None
        self.device = None
        self.plugin_manager = plugin_manager
        self.telemetry_engine = telemetry_engine
        self.swarm = swarm
        self.rl_agent = RLAgent()
        self.history_window = 16
        self._init_model()
        self._maybe_train_from_dataset()

    def _init_model(self):
        if torch is None:
            log("[AITranslatorEngine] Torch not available, using heuristic only.")
            return
        try:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model = TemporalTranslatorNet().to(self.device)
            self.model.eval()
            log(f"[AITranslatorEngine] TemporalTranslatorNet initialized on {self.device}.")
        except Exception as e:
            log(f"[AITranslatorEngine] Failed to init TemporalTranslatorNet: {e}")
            log(traceback.format_exc())
            self.model = None
            self.device = None

    def _encode_features(self, gpu: GPUInfo, driver: DriverInfo, mode: str, policy, benchmark_score: float, risk_info):
        mem_gb = gpu.memory_total_mb / 1024.0
        load_pct = gpu.load
        temp = float(gpu.temperature or 0.0)

        vendor_vec = [0.0, 0.0]
        if gpu.vendor.lower() == "nvidia":
            vendor_vec[0] = 1.0
        else:
            vendor_vec[1] = 1.0

        mode_vec = [0.0, 0.0, 0.0, 0.0]
        mode = mode.lower()
        if mode == "balanced":
            mode_vec[0] = 1.0
        elif mode == "performance":
            mode_vec[1] = 1.0
        elif mode == "eco":
            mode_vec[2] = 1.0
        else:
            mode_vec[3] = 1.0

        cuda_flag = 1.0 if driver.api_support.get("CUDA", False) else 0.0
        bench_norm = benchmark_score / 100.0 if benchmark_score > 0 else 0.0
        aggr = float(policy.get("aggressiveness", 1))

        features = [
            mem_gb, load_pct, temp,
            vendor_vec[0], vendor_vec[1],
            mode_vec[0], mode_vec[1], mode_vec[2], mode_vec[3],
            cuda_flag, bench_norm, aggr,
        ]
        return features

    def _heuristic_score(self, gpu: GPUInfo, mode: str, benchmark_score: float, policy, risk_info):
        base = gpu.memory_total_mb / 1024.0
        load_factor = max(0.1, 1.0 - gpu.load / 100.0)

        mode = mode.lower()
        if mode == "performance":
            mode_factor = 1.4
        elif mode == "eco":
            mode_factor = 0.8
        elif mode == "compatibility":
            mode_factor = 0.9
        else:
            mode_factor = 1.0

        bench_factor = 1.0 + (benchmark_score / 150.0)
        aggr = float(policy.get("aggressiveness", 1))
        aggr_factor = 1.0 + (aggr * 0.1)

        risk = float(risk_info.get("risk", 0.0))
        risk_penalty = 1.0 - 0.4 * risk

        score = base * load_factor * mode_factor * bench_factor * aggr_factor * risk_penalty * 10.0
        return score

    def _maybe_train_from_dataset(self):
        if self.model is None or self.device is None or torch is None:
            return
        if not os.path.exists(AI_DATASET_PATH):
            log("[AITranslatorEngine] No AI dataset found, skipping training.")
            return
        try:
            with open(AI_DATASET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list) or not data:
                log("[AITranslatorEngine] AI dataset empty, skipping training.")
                return

            xs = []
            ys = []
            for entry in data:
                feats_seq = entry.get("features_seq")
                target = entry.get("target")
                if feats_seq is None or target is None:
                    continue
                xs.append(feats_seq)
                ys.append([float(target)])

            x_tensor = torch.tensor(xs, dtype=torch.float32, device=self.device)
            y_tensor = torch.tensor(ys, dtype=torch.float32, device=self.device)

            self.model.train()
            opt = torch.optim.Adam(self.model.parameters(), lr=1e-3)
            loss_fn = torch.nn.MSELoss()

            for epoch in range(10):
                opt.zero_grad()
                pred = self.model(x_tensor)
                loss = loss_fn(pred, y_tensor)
                loss.backward()
                opt.step()
            self.model.eval()
            log("[AITranslatorEngine] Trained TemporalTranslatorNet from local dataset.")
        except Exception as e:
            log(f"[AITranslatorEngine] Training failed, continuing with default weights: {e}")
            log(traceback.format_exc())

    def build_profile(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced",
                      benchmark_score: float = 0.0, capabilities=None,
                      game_exe=None, policy=None):
        if policy is None:
            policy = {"type": "auto", "aggressiveness": 1}

        risk_info = self.telemetry_engine.compute_risk()
        self.swarm.update_node_state(gpu, risk_info, mode, game_exe)
        heuristic_score = self._heuristic_score(gpu, mode, benchmark_score, policy, risk_info)
        ai_score = heuristic_score

        if self.model is not None and self.device is not None and torch is not None:
            try:
                feats = self._encode_features(gpu, driver, mode, policy, benchmark_score, risk_info)
                seq = [feats] * self.history_window
                x = torch.tensor([seq], dtype=torch.float32, device=self.device)
                with torch.no_grad():
                    out = self.model(x)
                ai_score = float(out.item())
                log(f"[AITranslatorEngine] AI score={ai_score:.3f}, heuristic={heuristic_score:.3f}")
            except Exception as e:
                log(f"[AITranslatorEngine] AI inference failed, using heuristic only: {e}")
                log(traceback.format_exc())
                ai_score = heuristic_score
        else:
            log(f"[AITranslatorEngine] Using heuristic only, score={heuristic_score:.3f}")

        state_key = f"{gpu.name}|{mode}|{game_exe or 'NO_GAME'}"
        action = self.rl_agent.choose(state_key, risk_info.get("risk", 0.0))
        self.plugin_manager.on_rl_decision({"state": state_key, "action": action, "risk": risk_info.get("risk", 0.0)})

        if action == "soft":
            policy["aggressiveness"] = max(0, policy.get("aggressiveness", 1) - 1)
        elif action == "aggressive":
            policy["aggressiveness"] = min(3, policy.get("aggressiveness", 1) + 1)

        self.current_profile = TranslationProfile(
            gpu, driver, mode, ai_score, heuristic_score, benchmark_score,
            capabilities, game_exe, policy,
            aggressiveness=policy.get("aggressiveness", 1)
        )
        return self.current_profile

    def simulate_translation_score(self):
        if not self.current_profile:
            return 0.0
        return self.current_profile.ai_score

    def export_profile(self):
        if not self.current_profile:
            return None
        return self.current_profile.to_dict()

    def reward(self, gpu: GPUInfo, mode: str, game_exe: str, stable: bool):
        state_key = f"{gpu.name}|{mode}|{game_exe or 'NO_GAME'}"
        reward = 1.0 if stable else -0.5
        self.rl_agent.update(state_key, "balanced", reward)

# ======================================================================
# Benchmarking Engine
# ======================================================================

class BenchmarkEngine:
    def __init__(self):
        self.last_score = 0.0

    def run_microbench(self):
        if torch is None:
            log("[BenchmarkEngine] Torch not available, benchmark skipped.")
            self.last_score = 0.0
            return self.last_score
        try:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            size = 1024
            a = torch.randn((size, size), device=device)
            b = torch.randn((size, size), device=device)
            if device.type == "cuda":
                torch.cuda.synchronize()
            t0 = time.time()
            _ = torch.matmul(a, b)
            if device.type == "cuda":
                torch.cuda.synchronize()
            t1 = time.time()
            elapsed = t1 - t0
            ops = size * size * size
            gflops = (ops / elapsed) / 1e9
            self.last_score = gflops
            log(f"[BenchmarkEngine] Matmul benchmark: {gflops:.2f} GFLOPS (elapsed {elapsed:.3f}s)")
            return self.last_score
        except Exception as e:
            log(f"[BenchmarkEngine] Benchmark failed: {e}")
            log(traceback.format_exc())
            self.last_score = 0.0
            return self.last_score

# ======================================================================
# Profile & Settings Manager
# ======================================================================

class ProfileManager:
    def __init__(self, path=PROFILE_PATH):
        self.path = path
        self.profiles = self._load_all()

    def _load_all(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                log(f"[ProfileManager] Loaded {len(data)} profile(s).")
                return data
            return []
        except Exception as e:
            log(f"[ProfileManager] Failed to load profiles: {e}")
            log(traceback.format_exc())
            return []

    def save_profile(self, profile_dict):
        self.profiles.append(profile_dict)
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2)
            log("[ProfileManager] Profile saved.")
        except Exception as e:
            log(f"[ProfileManager] Failed to save profile: {e}")
            log(traceback.format_exc())

    def list_profiles(self):
        return self.profiles

    def find_profile_for_game(self, game_exe):
        if not game_exe:
            return None
        for p in self.profiles:
            if p.get("game_exe") == game_exe:
                return p
        return None

    def find_profile_by_index(self, index):
        if 0 <= index < len(self.profiles):
            return self.profiles[index]
        return None

class SettingsManager:
    def __init__(self, path=SETTINGS_PATH):
        self.path = path
        self.settings = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            log("[SettingsManager] No settings file, using defaults.")
            return {
                "auto_mode": True,
                "last_gpu_id": None,
                "last_driver_version": None,
                "last_mode": "balanced",
                "global_aggressiveness": 1,
                "default_game_policy": "auto",
                "manual_override": 0,
                "node_id": "node-1",
                "distributed_render_enabled": True,
            }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            log("[SettingsManager] Settings loaded.")
            return {
                "auto_mode": bool(data.get("auto_mode", True)),
                "last_gpu_id": data.get("last_gpu_id"),
                "last_driver_version": data.get("last_driver_version"),
                "last_mode": data.get("last_mode", "balanced"),
                "global_aggressiveness": int(data.get("global_aggressiveness", 1)),
                "default_game_policy": data.get("default_game_policy", "auto"),
                "manual_override": int(data.get("manual_override", 0)),
                "node_id": data.get("node_id", "node-1"),
                "distributed_render_enabled": bool(data.get("distributed_render_enabled", True)),
            }
        except Exception as e:
            log(f"[SettingsManager] Failed to load settings, using defaults: {e}")
            log(traceback.format_exc())
            return {
                "auto_mode": True,
                "last_gpu_id": None,
                "last_driver_version": None,
                "last_mode": "balanced",
                "global_aggressiveness": 1,
                "default_game_policy": "auto",
                "manual_override": 0,
                "node_id": "node-1",
                "distributed_render_enabled": True,
            }

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
            log("[SettingsManager] Settings saved.")
        except Exception as e:
            log(f"[SettingsManager] Failed to save settings: {e}")
            log(traceback.format_exc())

    def set_auto_mode(self, auto: bool):
        self.settings["auto_mode"] = bool(auto)
        self.save()

    def update_profile_info(self, gpu: GPUInfo, driver: DriverInfo, mode: str):
        self.settings["last_gpu_id"] = gpu.id_str
        self.settings["last_driver_version"] = driver.version
        self.settings["last_mode"] = mode
        self.save()

    def get_auto_mode(self):
        return bool(self.settings.get("auto_mode", True))

    def get_last_gpu_id(self):
        return self.settings.get("last_gpu_id")

    def get_last_driver_version(self):
        return self.settings.get("last_driver_version")

    def get_last_mode(self):
        return self.settings.get("last_mode", "balanced")

    def get_global_aggressiveness(self):
        return int(self.settings.get("global_aggressiveness", 1))

    def set_global_aggressiveness(self, value: int):
        self.settings["global_aggressiveness"] = max(0, min(3, int(value)))
        self.save()

    def get_default_game_policy(self):
        return self.settings.get("default_game_policy", "auto")

    def set_default_game_policy(self, policy: str):
        self.settings["default_game_policy"] = policy
        self.save()

    def get_manual_override(self):
        return int(self.settings.get("manual_override", 0))

    def set_manual_override(self, value: int):
        self.settings["manual_override"] = max(-3, min(3, int(value)))
        self.save()

    def get_node_id(self):
        return self.settings.get("node_id", "node-1")

    def set_node_id(self, node_id: str):
        self.settings["node_id"] = node_id
        self.save()

    def is_distributed_render_enabled(self):
        return bool(self.settings.get("distributed_render_enabled", True))

    def set_distributed_render_enabled(self, enabled: bool):
        self.settings["distributed_render_enabled"] = bool(enabled)
        self.save()

# ======================================================================
# Translation Policy & Task Engine
# ======================================================================

class TranslationPolicyEngine:
    def __init__(self, swarm: SwarmCoordinator, settings: SettingsManager):
        self.swarm = swarm
        self.settings = settings

    def build_policy_for_game(self, settings: SettingsManager, game_exe: str):
        base_type = settings.get_default_game_policy()
        base_aggr = settings.get_global_aggressiveness()
        manual_override = settings.get_manual_override()
        global_aggr = self.swarm.compute_global_aggressiveness(base_aggr)
        effective_aggr = global_aggr + manual_override
        effective_aggr = max(0, min(3, effective_aggr))
        return {
            "type": base_type,
            "aggressiveness": effective_aggr,
            "game_exe": game_exe,
            "base_aggressiveness": base_aggr,
            "global_aggressiveness": global_aggr,
            "manual_override": manual_override,
        }

    def describe_policy(self, policy):
        t = policy.get("type", "auto")
        aggr = policy.get("aggressiveness", 1)
        base = policy.get("base_aggressiveness", aggr)
        global_aggr = policy.get("global_aggressiveness", base)
        override = policy.get("manual_override", 0)
        return f"type={t}, effective={aggr} (base={base}, global={global_aggr}, override={override:+d})"

class TranslationTaskEngine:
    def shader_translation(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Shader translation policy={policy.get('type')} aggr={policy.get('aggressiveness')} "
            f"GPU={profile.gpu.name}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Shader translation pipeline configured (policy-driven stub).",
        }

    def driver_compat_translation(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Driver compatibility policy={policy.get('type')} "
            f"driver={profile.driver.version}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Driver compatibility mapping applied (policy-driven stub).",
        }

    def performance_tuning(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Performance tuning policy={policy.get('type')} aggr={policy.get('aggressiveness')} "
            f"AI score={profile.ai_score:.2f}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Performance tuning hints generated (policy-driven stub).",
        }

# ======================================================================
# Game Behavior Memory System
# ======================================================================

class GameMemory:
    def __init__(self, path=GAME_MEMORY_PATH, plugin_manager: PluginManager = None):
        self.path = path
        self.plugin_manager = plugin_manager
        self.memory = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                log("[GameMemory] Loaded game memory.")
                return data
            return {}
        except Exception as e:
            log(f"[GameMemory] Failed to load game memory: {e}")
            log(traceback.format_exc())
            return {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.memory, f, indent=2)
            log("[GameMemory] Game memory saved.")
        except Exception as e:
            log(f"[GameMemory] Failed to save game memory: {e}")
            log(traceback.format_exc())

    def _key(self, exe):
        return exe.lower()

    def update(self, exe, gpu_load, gpu_temp, ai_score, heuristic_score):
        key = self._key(exe)
        entry = self.memory.get(key, {
            "samples": 0,
            "avg_gpu_load": 0.0,
            "avg_gpu_temp": 0.0,
            "avg_ai_score": 0.0,
            "avg_heuristic_score": 0.0,
        })
        n = entry["samples"]
        entry["samples"] = n + 1
        entry["avg_gpu_load"] = (entry["avg_gpu_load"] * n + gpu_load) / (n + 1)
        entry["avg_gpu_temp"] = (entry["avg_gpu_temp"] * n + gpu_temp) / (n + 1)
        entry["avg_ai_score"] = (entry["avg_ai_score"] * n + ai_score) / (n + 1)
        entry["avg_heuristic_score"] = (entry["avg_heuristic_score"] * n + heuristic_score) / (n + 1)
        self.memory[key] = entry
        self.save()
        if self.plugin_manager:
            self.plugin_manager.on_game_memory_update(key, entry)

    def get(self, exe):
        return self.memory.get(self._key(exe))

# ======================================================================
# Advanced Game Detection v3 + Distributed Rendering + Borg + Board Integration
# ======================================================================

class GameSessionManager:
    def __init__(self, gpu_detector: GPUDetector, profile_manager: ProfileManager,
                 translator: AITranslatorEngine, driver_detector: DriverDetector,
                 benchmark_engine: BenchmarkEngine, settings_manager: SettingsManager,
                 plugin_manager: PluginManager, policy_engine: TranslationPolicyEngine,
                 game_memory: GameMemory, render_manager: DistributedRenderManager,
                 borg_network: BorgVramNetwork, board_network: BoardNeuralNetwork):
        self.gpu_detector = gpu_detector
        self.profile_manager = profile_manager
        self.translator = translator
        self.driver_detector = driver_detector
        self.benchmark_engine = benchmark_engine
        self.settings_manager = settings_manager
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.game_memory = game_memory
        self.render_manager = render_manager
        self.borg_network = borg_network
        self.board_network = board_network
        self.current_game_exe = None
        self.last_check_time = 0.0
        self.check_interval = 6.0

        self.known_game_keywords = [
            "eldenring", "fortnite", "doom", "cod", "battlefield",
            "cyberpunk", "witcher", "overwatch", "valorant", "leagueoflegends",
            "csgo", "cs2", "starfield", "minecraft", "roblox",
        ]

        self.ignore_keywords = [
            "steam", "epic", "uplay", "origin", "gog", "battle.net",
            "discord", "chrome", "edge", "firefox", "opera",
            "explorer", "shellexperiencehost", "dwm",
        ]

    def _pick_best_gpu(self):
        gpus = self.gpu_detector.gpus
        if not gpus:
            return None
        gpus_sorted = sorted(
            gpus,
            key=lambda g: (-g.memory_total_mb, g.load)
        )
        best = gpus_sorted[0]
        log(f"[GameSessionManager] Best GPU selected: {best.name} ({best.memory_total_mb} MB, load={best.load:.1f}%)")
        return best

    def _is_game_candidate(self, proc):
        try:
            name = (proc.name() or "").lower()
        except Exception:
            name = ""
        try:
            exe = (proc.exe() or "").lower()
        except Exception:
            exe = ""

        if not exe:
            return False

        for kw in self.ignore_keywords:
            if kw in name or kw in exe:
                return False

        for kw in self.known_game_keywords:
            if kw in name or kw in exe:
                return True

        if exe.endswith(".exe") and ("game" in exe or "games" in exe):
            return True

        return False

    def _collect_game_processes(self):
        if psutil is None:
            log("[GameSessionManager] psutil not available, game detection disabled.")
            return []

        candidates = []
        for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cpu_percent", "memory_info"]):
            try:
                if not self._is_game_candidate(proc):
                    continue
                info = proc.info
                cpu = info.get("cpu_percent", 0.0)
                exe = info.get("exe") or ""
                name = info.get("name") or ""
                mem = info.get("memory_info").rss if info.get("memory_info") else 0
                if not exe:
                    continue
                candidates.append({
                    "pid": info.get("pid"),
                    "name": name,
                    "exe": exe,
                    "cpu_percent": cpu,
                    "rss_bytes": mem,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log(f"[GameSessionManager] Process scan error: {e}")
        return candidates

    def _pick_active_game(self, candidates):
        if not candidates:
            return None
        active = sorted(
            candidates,
            key=lambda c: (-c["cpu_percent"], -c["rss_bytes"], c["name"].lower())
        )[0]
        return active

    def strict_detect_game(self):
        now = time.time()
        if now - self.last_check_time < self.check_interval:
            return None
        self.last_check_time = now

        candidates = self._collect_game_processes()
        active = self._pick_active_game(candidates)
        if not active:
            return None

        exe = active["exe"]
        name = active["name"]
        cpu = active["cpu_percent"]
        log(f"[GameSessionManager] Strict game candidate: {name} ({exe}), cpu={cpu:.1f}%")

        self.current_game_exe = exe
        return {
            "name": name,
            "exe": exe,
            "cpu_percent": cpu,
        }

    def build_or_reuse_profile_for_game(self, game_info):
        game_exe = game_info["exe"]
        existing = self.profile_manager.find_profile_for_game(game_exe)
        if existing:
            log(f"[GameSessionManager] Reusing existing profile for {game_exe}")
            return existing

        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        if not gpus or not drivers:
            log("[GameSessionManager] No GPU/driver for profile build.")
            return None

        best_gpu = self._pick_best_gpu()
        driver = drivers[0]

        bench_score = self.benchmark_engine.run_microbench()
        policy = self.policy_engine.build_policy_for_game(self.settings_manager, game_exe)
        profile = self.translator.build_profile(
            best_gpu,
            driver,
            mode=self.settings_manager.get_last_mode(),
            benchmark_score=bench_score,
            capabilities={"game_mode": True},
            game_exe=game_exe,
            policy=policy,
        )
        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)
        self.plugin_manager.on_game_detected(game_info, profile_dict)
        log(f"[GameSessionManager] New profile built for game {game_exe}")
        return profile_dict

    def maybe_request_distributed_render(self, game_exe: str, required_vram_mb: int, gpu: GPUInfo, risk_info: dict):
        if not self.settings_manager.is_distributed_render_enabled():
            return None

        gpus = self.gpu_detector.detect()
        if not gpus:
            return None
        best_gpu = self._pick_best_gpu()
        local_vram_mb = best_gpu.memory_total_mb

        if required_vram_mb <= local_vram_mb:
            return None

        task = self.render_manager.create_render_task(
            game_exe=game_exe,
            required_vram_mb=required_vram_mb,
            local_vram_mb=local_vram_mb,
        )
        if task:
            self.borg_network.apply_shortcuts_to_task(game_exe, task)
            self.board_network.apply_ideas_to_task(game_exe, task)
        return task

    def apply_policy_for_game(self, game_info, profile_dict):
        game_exe = game_info["exe"]
        policy = self.policy_engine.build_policy_for_game(self.settings_manager, game_exe)
        self.plugin_manager.on_policy_applied(policy)

        gpu_dict = profile_dict.get("gpu") or {}
        driver_dict = profile_dict.get("driver") or {}
        gpu = GPUInfo(
            name=gpu_dict.get("name", ""),
            id_str=gpu_dict.get("id", ""),
            memory_total_mb=gpu_dict.get("memory_total_mb", 0),
            load=gpu_dict.get("load", 0.0),
            driver_version=gpu_dict.get("driver_version", ""),
            vendor=gpu_dict.get("vendor", "unknown"),
            temperature=gpu_dict.get("temperature"),
            cuda_capability=gpu_dict.get("cuda_capability"),
        )
        driver = DriverInfo(
            name=driver_dict.get("name", ""),
            version=driver_dict.get("version", ""),
            api_support=driver_dict.get("api_support", {}),
        )

        profile = TranslationProfile(
            gpu=gpu,
            driver=driver,
            mode=profile_dict.get("mode", "balanced"),
            ai_score=profile_dict.get("ai_score", 0.0),
            heuristic_score=profile_dict.get("heuristic_score", 0.0),
            benchmark_score=profile_dict.get("benchmark_score", 0.0),
            capabilities=profile_dict.get("capabilities", {}),
            game_exe=profile_dict.get("game_exe"),
            policy=policy,
            aggressiveness=policy.get("aggressiveness", 1),
        )

        task_engine = TranslationTaskEngine()
        shader_res = task_engine.shader_translation(policy, profile)
        compat_res = task_engine.driver_compat_translation(policy, profile)
        perf_res = task_engine.performance_tuning(policy, profile)

        temp = float(gpu.temperature or 0.0)
        self.game_memory.update(game_exe, gpu.load, temp, profile.ai_score, profile.heuristic_score)

        self.borg_network.observe_render_activity(self.render_manager, self.game_memory)

        risk_info = self.translator.telemetry_engine.compute_risk()
        board_ideas = self.board_network.generate_out_of_box_ideas(
            game_exe,
            gpu,
            risk_info,
            self.render_manager,
            self.borg_network,
            self.game_memory,
        )

        required_vram_mb = 6144
        dr_task = self.maybe_request_distributed_render(game_exe, required_vram_mb, gpu, risk_info)
        if dr_task:
            log(f"[GameSessionManager] Distributed render requested for {game_exe}: deficit={dr_task['deficit_mb']} MB")

        log(f"[GameSessionManager] Policy applied for {game_exe}: "
            f"shader={shader_res['status']}, compat={compat_res['status']}, perf={perf_res['status']}")
        return {
            "policy": policy,
            "shader": shader_res,
            "compat": compat_res,
            "perf": perf_res,
            "distributed_render_task": dr_task,
            "board_ideas": board_ideas,
        }

# ======================================================================
# Qt GUI – Command Center + Game Detection Tab + GPU Governor Panel + Swarm + Distributed Rendering + Borg + Board
# ======================================================================

class GameCardWidget(QtWidgets.QFrame):
    applyRequested = QtCore.Signal(dict)

    def __init__(self, game_info, profile_dict, policy_engine: TranslationPolicyEngine,
                 settings: SettingsManager, borg_network: BorgVramNetwork,
                 board_network: BoardNeuralNetwork, parent=None):
        super().__init__(parent)
        self.game_info = game_info
        self.profile_dict = profile_dict
        self.policy_engine = policy_engine
        self.settings = settings
        self.borg_network = borg_network
        self.board_network = board_network

        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        self.setObjectName("GameCardWidget")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        title = QtWidgets.QLabel(f"{game_info['name']}  ({os.path.basename(game_info['exe'])})")
        title.setStyleSheet("font-weight: bold;")
        layout.addWidget(title)

        exe_label = QtWidgets.QLabel(game_info["exe"])
        exe_label.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(exe_label)

        ai_score = profile_dict.get("ai_score", 0.0)
        heuristic_score = profile_dict.get("heuristic_score", 0.0)
        bench_score = profile_dict.get("benchmark_score", 0.0)

        info_line = QtWidgets.QLabel(
            f"AI={ai_score:.2f}  Heuristic={heuristic_score:.2f}  Bench={bench_score:.2f} GFLOPS"
        )
        layout.addWidget(info_line)

        policy = self.policy_engine.build_policy_for_game(self.settings, game_info["exe"])
        policy_desc = QtWidgets.QLabel(self.policy_engine.describe_policy(policy))
        layout.addWidget(policy_desc)

        shortcuts = self.borg_network.get_shortcuts_for_game(game_info["exe"])
        if shortcuts:
            borg_label = QtWidgets.QLabel(
                "Borg shortcuts: " + ", ".join(s["type"] for s in shortcuts)
            )
            borg_label.setStyleSheet("color: #4a8; font-size: 10px;")
            layout.addWidget(borg_label)

        ideas = self.board_network.get_ideas_for_game(game_info["exe"])
        if ideas:
            board_label = QtWidgets.QLabel(
                "Board ideas: " + ", ".join(i["category"] for i in ideas)
            )
            board_label.setStyleSheet("color: #c84; font-size: 10px;")
            layout.addWidget(board_label)

        slider_layout = QtWidgets.QHBoxLayout()
        slider_label = QtWidgets.QLabel("Additive override:")
        slider_layout.addWidget(slider_label)

        self.override_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.override_slider.setMinimum(-3)
        self.override_slider.setMaximum(3)
        self.override_slider.setValue(self.settings.get_manual_override())
        self.override_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.override_slider.setTickInterval(1)
        slider_layout.addWidget(self.override_slider)

        self.override_value_label = QtWidgets.QLabel(f"{self.override_slider.value():+d}")
        slider_layout.addWidget(self.override_value_label)

        layout.addLayout(slider_layout)

        btn_layout = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Apply Policy")
        self.apply_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MediaPlay))
        btn_layout.addWidget(self.apply_btn)

        self.compare_btn = QtWidgets.QPushButton("Compare Scores")
        self.compare_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView))
        btn_layout.addWidget(self.compare_btn)

        layout.addLayout(btn_layout)

        self.apply_btn.clicked.connect(self._on_apply_clicked)
        self.override_slider.valueChanged.connect(self._on_override_changed)
        self.compare_btn.clicked.connect(self._on_compare_clicked)

    def _on_override_changed(self, value):
        self.override_value_label.setText(f"{value:+d}")
        self.settings.set_manual_override(value)

    def _on_apply_clicked(self):
        payload = {
            "game_info": self.game_info,
            "profile_dict": self.profile_dict,
        }
        self.applyRequested.emit(payload)

    def _on_compare_clicked(self):
        ai_score = self.profile_dict.get("ai_score", 0.0)
        heuristic_score = self.profile_dict.get("heuristic_score", 0.0)
        QtWidgets.QMessageBox.information(
            self,
            "Score Comparison",
            f"AI score: {ai_score:.3f}\nHeuristic score: {heuristic_score:.3f}",
        )

class GameDetectionTab(QtWidgets.QWidget):
    def __init__(self, game_session: GameSessionManager, settings: SettingsManager,
                 policy_engine: TranslationPolicyEngine, borg_network: BorgVramNetwork,
                 board_network: BoardNeuralNetwork, parent=None):
        super().__init__(parent)
        self.game_session = game_session
        self.settings = settings
        self.policy_engine = policy_engine
        self.borg_network = borg_network
        self.board_network = board_network

        self.cards = []
        self.last_game_exe = None

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("Game Detection (Strict v3, Non-Invasive)")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)

        self.refresh_btn = QtWidgets.QPushButton("Scan Now")
        self.refresh_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        header_layout.addWidget(self.refresh_btn)

        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(4, 4, 4, 4)
        self.scroll_layout.setSpacing(4)
        self.scroll.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll)

        self.status_label = QtWidgets.QLabel("No game detected yet.")
        self.status_label.setStyleSheet("color: #888; font-size: 10px;")
        main_layout.addWidget(self.status_label)

        self.refresh_btn.clicked.connect(self.scan_games)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(int(self.game_session.check_interval * 1000))
        self.timer.timeout.connect(self.scan_games)
        self.timer.start()

    def clear_cards(self):
        for card in self.cards:
            card.setParent(None)
        self.cards = []
        while self.scroll_layout.count():
            item = self.scroll_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def scan_games(self):
        game_info = self.game_session.strict_detect_game()

        if not game_info:
            if not self.cards:
                self.status_label.setText("No active game detected (strict filter v3).")
            return

        if self.last_game_exe == game_info["exe"] and self.cards:
            self.status_label.setText(
                f"Detected game: {game_info['name']} ({os.path.basename(game_info['exe'])})"
            )
            return

        self.last_game_exe = game_info["exe"]
        self.clear_cards()

        profile_dict = self.game_session.build_or_reuse_profile_for_game(game_info)
        if not profile_dict:
            self.status_label.setText("Game detected, but profile could not be built.")
            return

        card = GameCardWidget(
            game_info,
            profile_dict,
            self.policy_engine,
            self.settings,
            self.borg_network,
            self.board_network,
        )
        card.applyRequested.connect(self._on_apply_requested)
        self.scroll_layout.addWidget(card)
        self.cards.append(card)

        self.status_label.setText(
            f"Detected game: {game_info['name']} ({os.path.basename(game_info['exe'])})"
        )

    def _on_apply_requested(self, payload):
        game_info = payload["game_info"]
        profile_dict = payload["profile_dict"]
        res = self.game_session.apply_policy_for_game(game_info, profile_dict)

        dr_msg = ""
        if res.get("distributed_render_task"):
            t = res["distributed_render_task"]
            borg_hints = t.get("borg_hints", [])
            board_ideas = t.get("board_ideas", [])
            borg_text = "\nBorg hints: " + "; ".join(borg_hints) if borg_hints else ""
            board_text = "\nBoard ideas: " + "; ".join(board_ideas) if board_ideas else ""
            dr_msg = f"\nDistributed render requested: deficit={t['deficit_mb']} MB{borg_text}{board_text}"

        ideas_msg = ""
        if res.get("board_ideas"):
            ideas_msg = "\nBoard network ideas:\n" + "\n".join(
                f"- [{i['category']}] {i['description']}" for i in res["board_ideas"]
            )

        QtWidgets.QMessageBox.information(
            self,
            "Policy Applied",
            f"Policy: {self.policy_engine.describe_policy(res['policy'])}\n"
            f"Shader: {res['shader']['status']}\n"
            f"Compat: {res['compat']['status']}\n"
            f"Perf: {res['perf']['status']}{dr_msg}{ideas_msg}",
        )

class GPUOverviewTab(QtWidgets.QWidget):
    def __init__(self, gpu_detector: GPUDetector, driver_detector: DriverDetector,
                 translator: AITranslatorEngine, benchmark_engine: BenchmarkEngine,
                 profile_manager: ProfileManager, settings: SettingsManager,
                 plugin_manager: PluginManager, parent=None):
        super().__init__(parent)
        self.gpu_detector = gpu_detector
        self.driver_detector = driver_detector
        self.translator = translator
        self.benchmark_engine = benchmark_engine
        self.profile_manager = profile_manager
        self.settings = settings
        self.plugin_manager = plugin_manager

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("GPU Overview & Translation Profile")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)

        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        header_layout.addWidget(self.refresh_btn)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.info_text = QtWidgets.QTextEdit()
        self.info_text.setReadOnly(True)
        layout.addWidget(self.info_text)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["balanced", "performance", "eco", "compatibility"])
        self.mode_combo.setCurrentText(self.settings.get_last_mode())

        mode_layout = QtWidgets.QHBoxLayout()
        mode_layout.addWidget(QtWidgets.QLabel("Mode:"))
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        self.build_btn = QtWidgets.QPushButton("Build Profile")
        self.build_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogApplyButton))
        layout.addWidget(self.build_btn)

        self.refresh_btn.clicked.connect(self.refresh_info)
        self.build_btn.clicked.connect(self.build_profile)

        self.refresh_info()

    def refresh_info(self):
        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        lines = []
        lines.append(f"App version: {APP_VERSION}")
        lines.append("")
        if not gpus:
            lines.append("No GPUs detected.")
        else:
            lines.append(f"Detected {len(gpus)} GPU(s):")
            for g in gpus:
                lines.append(
                    f" - {g.name} (id={g.id_str}, {g.memory_total_mb} MB, load={g.load:.1f}%, "
                    f"driver={g.driver_version}, vendor={g.vendor}, cuda={g.cuda_capability})"
                )
        lines.append("")
        if not drivers:
            lines.append("No drivers detected.")
        else:
            lines.append(f"Detected {len(drivers)} driver(s):")
            for d in drivers:
                lines.append(
                    f" - {d.name} v{d.version} | DX={d.api_support.get('DirectX')} "
                    f"VK={d.api_support.get('Vulkan')} GL={d.api_support.get('OpenGL')} "
                    f"CUDA={d.api_support.get('CUDA')}"
                )
        self.info_text.setPlainText("\n".join(lines))

    def build_profile(self):
        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        if not gpus or not drivers:
            QtWidgets.QMessageBox.warning(self, "Profile", "No GPU/driver available.")
            return

        best_gpu = sorted(gpus, key=lambda g: (-g.memory_total_mb, g.load))[0]
        driver = drivers[0]
        mode = self.mode_combo.currentText()
        bench_score = self.benchmark_engine.run_microbench()

        policy = {
            "type": "auto",
            "aggressiveness": self.settings.get_global_aggressiveness(),
        }

        profile = self.translator.build_profile(
            best_gpu,
            driver,
            mode=mode,
            benchmark_score=bench_score,
            capabilities={"game_mode": False},
            game_exe=None,
            policy=policy,
        )
        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.settings.update_profile_info(best_gpu, driver, mode)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)

        QtWidgets.QMessageBox.information(
            self,
            "Profile Built",
            f"Profile built for {best_gpu.name} in {mode} mode.\n"
            f"AI score={profile.ai_score:.2f}, heuristic={profile.heuristic_score:.2f}",
        )

class SettingsTab(QtWidgets.QWidget):
    def __init__(self, settings: SettingsManager, parent=None):
        super().__init__(parent)
        self.settings = settings

        layout = QtWidgets.QFormLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.auto_mode_checkbox = QtWidgets.QCheckBox("Enable auto mode")
        self.auto_mode_checkbox.setChecked(self.settings.get_auto_mode())
        layout.addRow("Auto mode:", self.auto_mode_checkbox)

        self.global_aggr_spin = QtWidgets.QSpinBox()
        self.global_aggr_spin.setRange(0, 3)
        self.global_aggr_spin.setValue(self.settings.get_global_aggressiveness())
        layout.addRow("Global aggressiveness:", self.global_aggr_spin)

        self.default_policy_combo = QtWidgets.QComboBox()
        self.default_policy_combo.addItems(["auto", "performance", "eco", "compatibility"])
        self.default_policy_combo.setCurrentText(self.settings.get_default_game_policy())
        layout.addRow("Default game policy:", self.default_policy_combo)

        self.manual_override_spin = QtWidgets.QSpinBox()
        self.manual_override_spin.setRange(-3, 3)
        self.manual_override_spin.setValue(self.settings.get_manual_override())
        layout.addRow("Manual override:", self.manual_override_spin)

        self.node_id_edit = QtWidgets.QLineEdit(self.settings.get_node_id())
        layout.addRow("Node ID (swarm):", self.node_id_edit)

        self.distributed_render_checkbox = QtWidgets.QCheckBox("Enable distributed rendering (VRAM farm)")
        self.distributed_render_checkbox.setChecked(self.settings.is_distributed_render_enabled())
        layout.addRow("Distributed rendering:", self.distributed_render_checkbox)

        self.save_btn = QtWidgets.QPushButton("Save Settings")
        layout.addRow(self.save_btn)

        self.save_btn.clicked.connect(self.save_settings)

    def save_settings(self):
        self.settings.set_auto_mode(self.auto_mode_checkbox.isChecked())
        self.settings.set_global_aggressiveness(self.global_aggr_spin.value())
        self.settings.set_default_game_policy(self.default_policy_combo.currentText())
        self.settings.set_manual_override(self.manual_override_spin.value())
        self.settings.set_node_id(self.node_id_edit.text().strip() or "node-1")
        self.settings.set_distributed_render_enabled(self.distributed_render_checkbox.isChecked())
        QtWidgets.QMessageBox.information(self, "Settings", "Settings saved.")

class GPUGovernorTab(QtWidgets.QWidget):
    def __init__(self, gpu_detector: GPUDetector, telemetry_engine: PredictiveTelemetryEngine,
                 swarm: SwarmCoordinator, parent=None):
        super().__init__(parent)
        self.gpu_detector = gpu_detector
        self.telemetry_engine = telemetry_engine
        self.swarm = swarm

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("GPU Governor Panel (Telemetry + Predictions + Swarm)")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)

        self.refresh_btn = QtWidgets.QPushButton("Sample Now")
        self.refresh_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        header_layout.addWidget(self.refresh_btn)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.temp_label = QtWidgets.QLabel("Temp: N/A")
        self.load_label = QtWidgets.QLabel("Load: N/A")
        self.risk_label = QtWidgets.QLabel("Risk: N/A")
        self.swarm_label = QtWidgets.QLabel("Swarm: N/A")
        layout.addWidget(self.temp_label)
        layout.addWidget(self.load_label)
        layout.addWidget(self.risk_label)
        layout.addWidget(self.swarm_label)

        self.refresh_btn.clicked.connect(self.sample_once)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self.sample_once)
        self.timer.start()

    def sample_once(self):
        gpus = self.gpu_detector.detect()
        if not gpus:
            self.temp_label.setText("Temp: N/A")
            self.load_label.setText("Load: N/A")
            self.risk_label.setText("Risk: N/A")
            self.swarm_label.setText("Swarm: N/A")
            return

        best_gpu = sorted(gpus, key=lambda g: (-g.memory_total_mb, g.load))[0]
        self.telemetry_engine.sample(best_gpu)
        info = self.telemetry_engine.compute_risk()

        self.temp_label.setText(
            f"Temp: {best_gpu.temperature or 0:.1f}°C → projected {info['projected_temp']:.1f}°C"
        )
        self.load_label.setText(
            f"Load: {best_gpu.load:.1f}% → projected {info['projected_load']:.1f}%"
        )
        self.risk_label.setText(
            f"Risk: {info['risk']:.2f} (dT/dt={info['temp_slope']:.3f}, dLoad/dt={info['load_slope']:.3f})"
        )

        nodes = self.swarm.state.get("nodes", {})
        self.swarm_label.setText(
            f"Swarm nodes: {len(nodes)} | avg risk/load used for global aggressiveness"
        )

class DistributedRenderTab(QtWidgets.QWidget):
    def __init__(self, render_manager: DistributedRenderManager, settings: SettingsManager,
                 borg_network: BorgVramNetwork, board_network: BoardNeuralNetwork, parent=None):
        super().__init__(parent)
        self.render_manager = render_manager
        self.settings = settings
        self.borg_network = borg_network
        self.board_network = board_network

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("Distributed Rendering / VRAM Farm + Borg + Board Network")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.info_text = QtWidgets.QTextEdit()
        self.info_text.setReadOnly(True)
        layout.addWidget(self.info_text)

        self.refresh_btn = QtWidgets.QPushButton("Refresh Tasks, Shortcuts & Ideas")
        layout.addWidget(self.refresh_btn)

        self.refresh_btn.clicked.connect(self.refresh_tasks)
        self.refresh_tasks()

    def refresh_tasks(self):
        tasks = self.render_manager.tasks.get("tasks", [])
        results = self.render_manager.tasks.get("results", [])
        shortcuts = self.borg_network.shortcuts.get("shortcuts", [])
        ideas = self.board_network.ideas.get("ideas", [])
        lines = []
        lines.append(f"Node ID: {self.render_manager.node_id}")
        lines.append(f"Distributed rendering enabled: {self.settings.is_distributed_render_enabled()}")
        lines.append("")
        lines.append("Tasks:")
        if not tasks:
            lines.append("  (none)")
        else:
            for t in tasks:
                hints = t.get("borg_hints", [])
                board_ideas = t.get("board_ideas", [])
                hint_str = f" | Borg hints: {', '.join(hints)}" if hints else ""
                board_str = f" | Board ideas: {', '.join(board_ideas)}" if board_ideas else ""
                lines.append(
                    f"  - {t['id']} | game={t['game_exe']} | deficit={t['deficit_mb']} MB | "
                    f"status={t['status']} | assigned_to={t['assigned_to']}{hint_str}{board_str}"
                )
        lines.append("")
        lines.append("Results:")
        if not results:
            lines.append("  (none)")
        else:
            for r in results:
                lines.append(
                    f"  - task={r['task_id']} | node={r['node_id']} | quality={r['quality_hint']} | ts={r['ts']:.0f}"
                )
        lines.append("")
        lines.append("Borg VRAM Shortcuts:")
        if not shortcuts:
            lines.append("  (none)")
        else:
            for s in shortcuts:
                lines.append(
                    f"  - {s['id']} | game={s['game_exe']} | type={s['type']} | hint={s['hint']}"
                )
        lines.append("")
        lines.append("Board Network Ideas:")
        if not ideas:
            lines.append("  (none)")
        else:
            for i in ideas:
                lines.append(
                    f"  - {i['id']} | game={i['game_exe']} | category={i['category']} | desc={i['description']}"
                )
        self.info_text.setPlainText("\n".join(lines))

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Universal GPU Translator Command Center")
        self.resize(1200, 750)

        self.plugin_manager = PluginManager()
        self.settings_manager = SettingsManager()
        self.gpu_detector = GPUDetector()
        self.driver_detector = DriverDetector(self.gpu_detector)
        self.telemetry_engine = PredictiveTelemetryEngine(self.plugin_manager)
        self.swarm = SwarmCoordinator(self.settings_manager.get_node_id(), self.plugin_manager)
        self.benchmark_engine = BenchmarkEngine()
        self.profile_manager = ProfileManager()
        self.game_memory = GameMemory(plugin_manager=self.plugin_manager)
        self.render_manager = DistributedRenderManager(self.settings_manager.get_node_id(), self.plugin_manager)
        self.borg_network = BorgVramNetwork(self.plugin_manager)
        self.board_network = BoardNeuralNetwork(self.plugin_manager)
        self.policy_engine = TranslationPolicyEngine(self.swarm, self.settings_manager)
        self.translator = AITranslatorEngine(self.plugin_manager, self.telemetry_engine, self.swarm)
        self.game_session = GameSessionManager(
            self.gpu_detector,
            self.profile_manager,
            self.translator,
            self.driver_detector,
            self.benchmark_engine,
            self.settings_manager,
            self.plugin_manager,
            self.policy_engine,
            self.game_memory,
            self.render_manager,
            self.borg_network,
            self.board_network,
        )

        self.tab_widget = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.gpu_tab = GPUOverviewTab(
            self.gpu_detector,
            self.driver_detector,
            self.translator,
            self.benchmark_engine,
            self.profile_manager,
            self.settings_manager,
            self.plugin_manager,
        )
        self.game_tab = GameDetectionTab(
            self.game_session,
            self.settings_manager,
            self.policy_engine,
            self.borg_network,
            self.board_network,
        )
        self.governor_tab = GPUGovernorTab(self.gpu_detector, self.telemetry_engine, self.swarm)
        self.settings_tab = SettingsTab(self.settings_manager)
        self.render_tab = DistributedRenderTab(self.render_manager, self.settings_manager, self.borg_network, self.board_network)

        self.tab_widget.addTab(self.gpu_tab, "GPU & Profiles")
        self.tab_widget.addTab(self.game_tab, "Game Detection")
        self.tab_widget.addTab(self.governor_tab, "GPU Governor / Swarm")
        self.tab_widget.addTab(self.render_tab, "Distributed Rendering / Borg / Board")
        self.tab_widget.addTab(self.settings_tab, "Settings")

        self._setup_style()

    def _setup_style(self):
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        self.tab_widget.setDocumentMode(True)

# ======================================================================
# Entry Point
# ======================================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
