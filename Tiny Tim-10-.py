#!/usr/bin/env python3
"""
Unified LLM Dissector System (Next Evolution, Async Batching Fix, All Upgrades)
Local-Only, All Backends Auto-Detect, Copilot Fallback,
Cockpit Ultra Mode + Advanced Quantization + Tkinter Main-Thread Fix
+ Keep-Awake Mode + Full Web Integration + Copilot Backend Fix
+ Stats Loop Fix (kwargs-safe enqueue)
+ Chapter Layer (cluster → chapters → routed answering)
+ Persistent Knowledge Graph
+ Auto-Generated Chapter Titles & Summaries
+ Multi-Layer Chapters (subtopics)
+ Knowledge Graph Builder & Visualization
+ Web → Chapter Correlation Engine
+ Multi-Model Ensemble Answering (weighted + confidence)
+ GPU Heatmap (textual) Visualization
+ Prompt Templates & Inference Controls
+ Semantic Search
+ Chapter Merging (merge fix applied)
+ Auto-Tagging
+ Browser Extension Hooks / API (file-based integration)
+ Embedding Visualizer (graphical PCA/UMAP)
+ Real-Time Graph Updates & Animation
+ Query Rewriter
+ Multi-Hop Recursive Retrieval
+ Weighted Routing
+ Confidence-Based Tool Selection
+ Retrieval Caching
+ Hybrid Embeddings (dual-model)
+ Query Decomposition
+ Tool-Like Reasoning Modules (multi-agent)
+ Contextual Memory + Decay
+ Multi-Agent Reasoning
+ Real-Time Routing Visualization
+ Chapter Refinement Over Time
+ Adaptive Learning Mode
+ Chapter Search Bar
+ Explain-My-Answer Mode
+ Graphical Embedding Plots (PCA/UMAP)
+ Semantic Drift Detection & Auto-Correction
+ Multi-Agent Arbitration with Weighted Voting
+ Chapter Evolution Timeline
+ Adaptive Routing Weights
+ Self-Consistency Scoring
+ Chapter Evolution Heuristics (merge/split)
+ Graph-Based Routing
+ Multi-Hop Recursive Retrieval
+ Semantic Pruning
+ Async Inference Batching (FIXED: no duplicate max_new_tokens)
+ GPU-Aware Routing (textual)
+ Embedding Caching with TTL
+ Chapter Preloading (via refinement)
+ Memory-Based Warm Starts
+ Routing Heatmaps
+ Web → Chapter Auto-Tagging
+ Web-Triggered Chapter Refinement
"""

import sys
import platform
import importlib
import subprocess
import os
import shutil
import json
import threading
import time
import queue
from typing import Dict, List, Any, Optional, Tuple

# =========================
# PACKAGE AUTOLOADER
# =========================

class AutoLoader:
    def __init__(self):
        self.os_name = platform.system().lower()
        self.python_exec = sys.executable
        self.required_packages: Dict[str, str] = {
            "torch": "torch",
            "transformers": "transformers",
            "sentence_transformers": "sentence-transformers",
            "sklearn": "scikit-learn",
            "psutil": "psutil",
            "numpy": "numpy",
            "requests": "requests",
            "tkinter": "tk",
            "matplotlib": "matplotlib",
            "umap": "umap-learn",
        }
        self.loaded_modules: Dict[str, Any] = {}

    def install(self, package: str) -> None:
        try:
            subprocess.check_call(
                [self.python_exec, "-m", "pip", "install", package]
            )
        except Exception as e:
            print(f"[AutoLoader] Failed to install {package}: {e}")

    def load(self, module_name: str):
        try:
            module = importlib.import_module(module_name)
            self.loaded_modules[module_name] = module
            return module
        except ImportError:
            if module_name == "tkinter":
                print("[AutoLoader] tkinter missing; GUI may not work on this environment.")
                return None
            print(f"[AutoLoader] Missing: {module_name}. Installing...")
            self.install(self.required_packages[module_name])
            try:
                module = importlib.import_module(module_name)
                self.loaded_modules[module_name] = module
                return module
            except Exception as e:
                print(f"[AutoLoader] Could not load {module_name} after install: {e}")
                return None

    def load_all(self) -> Dict[str, Any]:
        print(f"[AutoLoader] OS detected: {self.os_name}")
        print(f"[AutoLoader] Python executable: {self.python_exec}")
        for module_name in self.required_packages:
            self.load(module_name)
        print("[AutoLoader] All modules attempted.")
        return self.loaded_modules


_loader = AutoLoader()
_modules = _loader.load_all()

np = _modules.get("numpy")
psutil = _modules.get("psutil")
torch = _modules.get("torch")
transformers = _modules.get("transformers")
sentence_transformers = _modules.get("sentence_transformers")
sklearn = _modules.get("sklearn")
requests = _modules.get("requests")
tkinter = _modules.get("tkinter")
matplotlib = _modules.get("matplotlib")
umap = _modules.get("umap")

if None in (np, psutil, torch, transformers, sentence_transformers, sklearn, requests):
    print("[System] Critical modules missing; exiting.")
    sys.exit(1)

from transformers import AutoModelForCausalLM, AutoTokenizer
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

if matplotlib is not None:
    import matplotlib.pyplot as plt

# =========================
# BEAST MODE CPU
# =========================

class BeastModeCPU:
    def __init__(self, reserve_cores: int = 2):
        self.reserve_cores = max(0, reserve_cores)

    def apply(self, pid: int = None) -> None:
        if pid is None:
            pid = psutil.Process().pid
        proc = psutil.Process(pid)
        all_cores = list(range(psutil.cpu_count()))
        if len(all_cores) <= self.reserve_cores:
            usable = all_cores
        else:
            usable = all_cores[:-self.reserve_cores]
        try:
            proc.cpu_affinity(usable)
        except Exception as e:
            print(f"[BeastModeCPU] Failed to set affinity: {e}")

# =========================
# ACTIVATION RECORDER (Torch-only)
# =========================

class ActivationRecorder:
    def __init__(self):
        self.records: List[np.ndarray] = []
        self._hooks = []

    def hook_layer(self, module: torch.nn.Module) -> None:
        def hook_fn(_module, _input, output):
            act = output.detach().cpu().numpy()
            self.records.append(act.reshape(-1))
        h = module.register_forward_hook(hook_fn)
        self._hooks.append(h)

    def clear(self) -> None:
        self.records = []

    def remove_hooks(self) -> None:
        for h in self._hooks:
            h.remove()
        self._hooks = []

    def get_matrix(self) -> np.ndarray:
        if not self.records:
            return np.zeros((0, 0), dtype=np.float32)
        return np.stack(self.records, axis=0)

# =========================
# ADVANCED QUANTIZATION MANAGER
# =========================

class QuantizationManager:
    def __init__(self, cockpit=None):
        self.cockpit = cockpit
        self.fp16 = os.getenv("QUANT_FP16", "1") == "1"
        self.bf16 = os.getenv("QUANT_BF16", "0") == "1"
        self.int8 = os.getenv("QUANT_INT8", "1") == "1"
        self.int8_perchan = os.getenv("QUANT_INT8_PERCHAN", "0") == "1"

    def log(self, msg):
        if self.cockpit:
            self.cockpit.log(f"[QUANT] {msg}")
        else:
            print("[QUANT]", msg)

    def apply(self, backend, model):
        if model is None:
            self.log("No Torch model loaded; skipping quantization.")
            return None

        if backend in ["gguf", "gpt4all", "lmstudio", "ollama", "copilot"]:
            self.log(f"Backend '{backend}' uses pre‑quantized or external models; leaving as is.")
            return model

        self.log(f"Applying advanced quantization for backend '{backend}'.")

        try:
            if self.bf16 and hasattr(torch, "bfloat16"):
                self.log("Converting model to BF16...")
                model.to(dtype=torch.bfloat16)
            elif self.fp16:
                self.log("Converting model to FP16...")
                model.half()

            if self.int8 and not torch.cuda.is_available():
                self.log("Applying INT8 dynamic quantization on Linear layers (CPU)...")
                model = torch.quantization.quantize_dynamic(
                    model,
                    {torch.nn.Linear},
                    dtype=torch.qint8
                )
                if self.int8_perchan:
                    self.log("Per-channel INT8 intent enabled (using dynamic quantization as approximation).")
                self.log("INT8 quantization applied.")

            self.log("Quantization complete.")
            return model

        except Exception as e:
            self.log(f"Quantization failed: {e}")
            return model

# =========================
# LOCAL-ONLY LLM LOADER (ALL BACKENDS + COPILOT FALLBACK)
# =========================

class LocalLLM_AutoLoader:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.beast = BeastModeCPU(reserve_cores=2)

    def detect_backend(self, model_path: str = None) -> str:
        import socket
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect(("127.0.0.1", 1234))
            s.close()
            return "lmstudio"
        except:
            pass

        if shutil.which("ollama"):
            return "ollama"

        if os.path.exists("models/"):
            for f in os.listdir("models/"):
                if f.endswith(".bin") or f.endswith(".gguf"):
                    return "gpt4all"

        if model_path and model_path.endswith(".gguf"):
            return "gguf"
        for f in os.listdir("."):
            if f.endswith(".gguf"):
                return "gguf"

        if model_path and (model_path.endswith(".safetensors") or os.path.isdir(model_path)):
            return "safetensors"

        return "copilot"

    def load(self, model_path: str = None):
        backend = self.detect_backend(model_path)
        print(f"[LocalLLM_AutoLoader] Using backend: {backend}")
        self.beast.apply()

        if backend == "lmstudio":
            return self.wrap_lmstudio(), backend, None
        if backend == "ollama":
            return self.wrap_ollama(), backend, None
        if backend == "gpt4all":
            return self.wrap_gpt4all(model_path), backend, None
        if backend == "gguf":
            return self.wrap_gguf(model_path), backend, None
        if backend == "safetensors":
            infer, model = self.wrap_safetensors(model_path)
            return infer, backend, model
        if backend == "copilot":
            return self.wrap_copilot(), backend, None

    def wrap_lmstudio(self):
        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            r = requests.post(
                "http://127.0.0.1:1234/v1/chat/completions",
                json={
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_new_tokens,
                }
            )
            j = r.json()
            return j["choices"][0]["message"]["content"]
        return infer

    def wrap_ollama(self):
        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            result = subprocess.run(
                ["ollama", "run", "llama3", prompt],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        return infer

    def wrap_gpt4all(self, model_path: str = None):
        try:
            from gpt4all import GPT4All
        except ImportError:
            print("[LocalLLM_AutoLoader] GPT4All not installed.")
            raise

        if model_path is None:
            for f in os.listdir("models/"):
                if f.endswith(".bin") or f.endswith(".gguf"):
                    model_path = os.path.join("models/", f)
                    break

        if model_path is None:
            raise RuntimeError("No GPT4All model found in models/.")

        model = GPT4All(model_path)

        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            return model.prompt(prompt)
        return infer

    def wrap_gguf(self, model_path: str = None):
        try:
            from llama_cpp import Llama
        except ImportError:
            print("[LocalLLM_AutoLoader] llama_cpp not installed.")
            raise

        if model_path is None:
            for f in os.listdir("."):
                if f.endswith(".gguf"):
                    model_path = f
                    break

        if model_path is None:
            raise RuntimeError("No GGUF model found in current directory.")

        llm = Llama(model_path=model_path)

        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            out = llm(prompt, max_tokens=max_new_tokens)
            return out["choices"][0]["text"]
        return infer

    def wrap_safetensors(self, model_path: str):
        if os.path.isdir(model_path):
            tokenizer = AutoTokenizer.from_pretrained(model_path)
            model = AutoModelForCausalLM.from_pretrained(model_path).to(self.device)
        else:
            base = os.path.splitext(model_path)[0]
            tokenizer = AutoTokenizer.from_pretrained(base)
            model = AutoModelForCausalLM.from_pretrained(base).to(self.device)

        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            inputs = tokenizer(prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=kwargs.get("do_sample", False),
                    temperature=kwargs.get("temperature", 0.7),
                    top_k=kwargs.get("top_k", 50),
                    top_p=kwargs.get("top_p", 0.9),
                )
            return tokenizer.decode(outputs[0], skip_special_tokens=True)

        return infer, model

    def wrap_copilot(self):
        class CopilotFallback:
            def infer(self, prompt: str, max_new_tokens: int = 256, **kwargs):
                return f"[Copilot Fallback Active] {prompt}"

        backend = CopilotFallback()

        def infer(prompt: str, max_new_tokens: int = 256, **kwargs):
            return backend.infer(prompt, max_new_tokens=max_new_tokens, **kwargs)

        return infer

# =========================
# PROMPT TEMPLATES & INFERENCE CONTROLS
# =========================

DEFAULT_PROMPT_TEMPLATES = {
    "qa": "User: {question}\nAnswer clearly and precisely:",
    "chapter_qa": "{chapter_title}\n{chapter_summary}\n\n{context}\n\n---\n\nUser: {question}\nAnswer clearly and precisely:",
    "rewrite": "Rewrite the following question to be clearer and more precise, preserving intent:\n\n{question}",
    "decompose": "Break the following question into 2-5 smaller sub-questions that help answer it:\n\n{question}\n\nList them as bullet points.",
    "explain": (
        "You are an explanation engine.\n\n"
        "Original question:\n{question}\n\n"
        "Final answer:\n{answer}\n\n"
        "Explain step-by-step how this answer was derived, including:\n"
        "- Which topics were relevant\n"
        "- Why certain information was used\n"
        "- Any assumptions made\n"
        "Keep it concise but clear."
    ),
    "multi_agent": (
        "You are Agent {agent_id} in a multi-agent reasoning system.\n\n"
        "Question:\n{question}\n\n"
        "Other agent's draft answer:\n{other_answer}\n\n"
        "Provide either:\n"
        "- A refined answer if you agree, or\n"
        "- A corrected answer if you disagree.\n"
        "Be direct and technical."
    ),
    "arbitration": (
        "You are an arbitration engine.\n\n"
        "Question:\n{question}\n\n"
        "Answer A:\n{answer_a}\n\n"
        "Answer B:\n{answer_b}\n\n"
        "Compare both answers and produce a final, best answer.\n"
        "Explain briefly why you chose it."
    ),
    "drift_detect": (
        "You are a semantic drift detector.\n\n"
        "Original summary:\n{old_summary}\n\n"
        "New summary:\n{new_summary}\n\n"
        "Recent Q&A:\n{qas}\n\n"
        "Explain whether the chapter meaning has drifted significantly.\n"
        "Answer with: DRIFT: yes/no\nReason: <short reason>"
    ),
    "self_consistency": (
        "You are checking self-consistency.\n\n"
        "Question:\n{question}\n\n"
        "Candidate answer:\n{answer}\n\n"
        "Rate how good this answer is from 0 to 1.\n"
        "Respond with: SCORE: <number between 0 and 1>"
    ),
}

DEFAULT_INFERENCE_CONFIG = {
    "temperature": 0.7,
    "top_k": 50,
    "top_p": 0.9,
    "max_new_tokens": 256,
}

# =========================
# SIMPLE CONTEXTUAL MEMORY WITH DECAY
# =========================

class ContextMemory:
    def __init__(self, max_items: int = 50, decay_half_life: float = 300.0):
        self.max_items = max_items
        self.decay_half_life = decay_half_life
        self.items: List[Dict[str, Any]] = []

    def add(self, question: str, chapter_id: Optional[str], tags: List[str]):
        self.items.append({
            "q": question,
            "chapter": chapter_id,
            "tags": tags,
            "time": time.time(),
        })
        if len(self.items) > self.max_items:
            self.items.pop(0)

    def _weight(self, t: float) -> float:
        age = time.time() - t
        return 0.5 ** (age / self.decay_half_life)

    def recent_tags(self) -> List[str]:
        tag_weights: Dict[str, float] = {}
        for item in self.items:
            w = self._weight(item["time"])
            for tag in item.get("tags", []):
                tag_weights[tag] = tag_weights.get(tag, 0.0) + w
        return [t for t, w in sorted(tag_weights.items(), key=lambda x: x[1], reverse=True) if w > 0.1]

    def recent_chapters(self) -> List[str]:
        chapter_weights: Dict[str, float] = {}
        for item in self.items:
            if item["chapter"] is None:
                continue
            w = self._weight(item["time"])
            chapter_weights[item["chapter"]] = chapter_weights.get(item["chapter"], 0.0) + w
        return [c for c, w in sorted(chapter_weights.items(), key=lambda x: x[1], reverse=True) if w > 0.1]

# =========================
# COCKPIT ULTRA GUI
# =========================

LLMCockpitGUI = None
if tkinter is not None:
    import tkinter as tk
    from tkinter import ttk, scrolledtext

    class LLMCockpitGUI:
        def __init__(self, backend_name="unknown", model_ids: List[str] = None):
            self.backend_name = backend_name
            self.active = False
            self.running = True
            self.last_activity = time.time()
            self.gui_queue = queue.Queue()
            self.model_ids = model_ids or []
            self.keep_awake_flag = True

            self.root = tk.Tk()
            self.root.title("LLM Cockpit Interface (Ultra Mode)")
            self.root.geometry("1900x1000")
            self.root.resizable(False, False)
            self.root.withdraw()

            self.tabs = ttk.Notebook(self.root)
            self.tabs.pack(fill="both", expand=True)

            # Status tab
            self.status_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.status_tab, text="Status")

            self.backend_label = tk.Label(self.status_tab, text=f"Backend: {self.backend_name}", font=("Arial", 16))
            self.backend_label.pack(pady=10)

            self.status_label = tk.Label(self.status_tab, text="Status: Idle", font=("Arial", 14))
            self.status_label.pack(pady=5)

            self.activity_indicator = tk.Label(self.status_tab, text="●", font=("Arial", 40), fg="gray")
            self.activity_indicator.pack(pady=10)

            # System Monitor tab
            self.monitor_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.monitor_tab, text="System Monitor")

            self.cpu_label = tk.Label(self.monitor_tab, text="CPU: 0%", font=("Arial", 14))
            self.cpu_label.pack(pady=10)

            self.ram_label = tk.Label(self.monitor_tab, text="RAM: 0%", font=("Arial", 14))
            self.ram_label.pack(pady=10)

            self.gpu_label = tk.Label(self.monitor_tab, text="GPU: N/A", font=("Arial", 14))
            self.gpu_label.pack(pady=10)

            self.gpu_heatmap = scrolledtext.ScrolledText(self.monitor_tab, width=80, height=10, font=("Consolas", 9))
            self.gpu_heatmap.pack(pady=10)

            # Inference Console tab
            self.console_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.console_tab, text="Inference Console")

            self.console = scrolledtext.ScrolledText(self.console_tab, width=120, height=25, font=("Consolas", 10))
            self.console.pack(pady=10)

            # Backend tab
            self.backend_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.backend_tab, text="Backend")

            self.backend_info = tk.Label(self.backend_tab, text=f"Active Backend: {self.backend_name}", font=("Arial", 14))
            self.backend_info.pack(pady=10)

            self.reload_button = tk.Button(self.backend_tab, text="Reload Backend", command=self._reload_backend_safe)
            self.reload_button.pack(pady=10)

            # Patterns tab
            self.patterns_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.patterns_tab, text="Patterns")

            self.patterns_info = scrolledtext.ScrolledText(self.patterns_tab, width=120, height=25, font=("Consolas", 10))
            self.patterns_info.pack(pady=10)

            # Models tab
            self.models_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.models_tab, text="Models")

            self.models_label = tk.Label(self.models_tab, text="Available Models:", font=("Arial", 14))
            self.models_label.pack(pady=10)

            self.models_list = tk.Listbox(self.models_tab, width=50, height=10)
            self.models_list.pack(pady=10)
            for mid in self.model_ids:
                self.models_list.insert(tk.END, mid)

            self.model_select_label = tk.Label(self.models_tab, text="(Selection is logical only; backend auto-detects)", font=("Arial", 10))
            self.model_select_label.pack(pady=5)

            # Web tab
            self.web_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.web_tab, text="Web")

            self.web_status_label = tk.Label(self.web_tab, text="Web Status: Idle", font=("Arial", 14))
            self.web_status_label.pack(pady=10)

            self.web_url_label = tk.Label(self.web_tab, text="Active URL: (none)", font=("Arial", 12))
            self.web_url_label.pack(pady=5)

            self.web_log = scrolledtext.ScrolledText(self.web_tab, width=120, height=20, font=("Consolas", 10))
            self.web_log.pack(pady=10)

            # Chapters / Graph / Embeddings / Routing / Plots tab
            self.chapters_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.chapters_tab, text="Chapters / Graph / Embeddings / Routing / Plots")

            left_frame = ttk.Frame(self.chapters_tab)
            left_frame.pack(side="left", padx=10, pady=10)

            mid_frame = ttk.Frame(self.chapters_tab)
            mid_frame.pack(side="left", padx=10, pady=10)

            right_frame = ttk.Frame(self.chapters_tab)
            right_frame.pack(side="left", padx=10, pady=10)

            extra_frame = ttk.Frame(self.chapters_tab)
            extra_frame.pack(side="left", padx=10, pady=10)

            # Chapter search bar
            self.search_label = tk.Label(left_frame, text="Chapter Search:", font=("Arial", 12))
            self.search_label.pack(pady=5)

            self.search_entry = tk.Entry(left_frame, width=40)
            self.search_entry.pack(pady=5)

            self.search_button = tk.Button(left_frame, text="Search", command=self._search_chapters_safe)
            self.search_button.pack(pady=5)

            self.chapters_list = scrolledtext.ScrolledText(left_frame, width=60, height=25, font=("Consolas", 10))
            self.chapters_list.pack(pady=10)

            # Graph view
            self.graph_view = scrolledtext.ScrolledText(mid_frame, width=60, height=25, font=("Consolas", 10))
            self.graph_view.pack(pady=10)

            # Embedding view
            self.embedding_view = scrolledtext.ScrolledText(right_frame, width=60, height=12, font=("Consolas", 10))
            self.embedding_view.pack(pady=5)

            # Routing view
            self.routing_view = scrolledtext.ScrolledText(right_frame, width=60, height=12, font=("Consolas", 10))
            self.routing_view.pack(pady=5)

            # Plot status
            self.plot_status_label = tk.Label(extra_frame, text="Embedding Plot: (not generated)", font=("Arial", 12))
            self.plot_status_label.pack(pady=5)

            self.plot_button_pca = tk.Button(extra_frame, text="Generate PCA Plot", command=self._generate_plot_pca_safe)
            self.plot_button_pca.pack(pady=5)

            self.plot_button_umap = tk.Button(
                extra_frame,
                text="Generate UMAP Plot",
                command=self._generate_plot_umap_safe
            )
            self.plot_button_umap.pack(pady=5)

            self.timeline_view = scrolledtext.ScrolledText(extra_frame, width=60, height=18, font=("Consolas", 10))
            self.timeline_view.pack(pady=5)

            self.routing_heatmap_view = scrolledtext.ScrolledText(extra_frame, width=60, height=8, font=("Consolas", 10))
            self.routing_heatmap_view.pack(pady=5)

            # --- caches MUST be initialized before threads (race fix) ---
            self._chapters_cache_text = ""
            self._chapters_cache_json: Dict[str, Any] = {}
            self._embedding_cache: Optional[np.ndarray] = None
            self._embedding_meta_cache: List[Dict[str, Any]] = []
            self._graph_text_cache = ""

            self.root.after(100, self._process_gui_queue)
            threading.Thread(target=self._stats_loop, daemon=True).start()
            threading.Thread(target=self._auto_hide_loop, daemon=True).start()
            threading.Thread(target=self._graph_animation_loop, daemon=True).start()

        def _enqueue(self, func, *args, **kwargs):
            self.gui_queue.put((func, args, kwargs))

        def _process_gui_queue(self):
            while not self.gui_queue.empty():
                func, args, kwargs = self.gui_queue.get()
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    print("GUI update error:", e)
            self.root.after(100, self._process_gui_queue)

        def set_active(self, is_active: bool):
            self._enqueue(self._set_active_gui, is_active)

        def log(self, text: str):
            self._enqueue(self._log_gui, text)

        def log_patterns(self, text: str):
            self._enqueue(self._log_patterns_gui, text)

        def log_web(self, text: str):
            self._enqueue(self._log_web_gui, text)

        def set_backend(self, backend: str):
            self._enqueue(self._set_backend_gui, backend)

        def set_web_status(self, status: str):
            self._enqueue(self._set_web_status_gui, status)

        def set_web_url(self, url: str):
            self._enqueue(self._set_web_url_gui, url)

        def update_chapters_view(self, text: str, chapters_json: Dict[str, Any]):
            self._chapters_cache_text = text
            self._chapters_cache_json = chapters_json
            self._enqueue(self._update_chapters_gui, text)

        def update_graph_view(self, text: str):
            self._graph_text_cache = text
            self._enqueue(self._update_graph_gui, text)

        def update_gpu_heatmap(self, text: str):
            self._enqueue(self._update_gpu_heatmap_gui, text)

        def update_embedding_view(self, text: str, embeddings: Optional[np.ndarray] = None, meta: Optional[List[Dict[str, Any]]] = None):
            if embeddings is not None:
                self._embedding_cache = embeddings
            if meta is not None:
                self._embedding_meta_cache = meta
            self._enqueue(self._update_embedding_gui, text)

        def update_routing_view(self, text: str):
            self._enqueue(self._update_routing_gui, text)

        def update_timeline_view(self, text: str):
            self._enqueue(self._update_timeline_gui, text)

        def update_routing_heatmap(self, text: str):
            self._enqueue(self._update_routing_heatmap_gui, text)

        def keep_awake(self):
            self.keep_awake_flag = True
            self._enqueue(self._set_active_gui, True)

        def allow_auto_hide(self):
            self.keep_awake_flag = False

        def _set_active_gui(self, is_active):
            self.active = is_active
            self.last_activity = time.time()
            if is_active:
                self.activity_indicator.config(text="●", fg="green")
                self.status_label.config(text="Status: Active")
                self.root.deiconify()
            else:
                self.activity_indicator.config(text="●", fg="gray")
                self.status_label.config(text="Status: Idle")

        def _log_gui(self, text):
            self.console.insert(tk.END, text + "\n")
            self.console.see(tk.END)

        def _log_patterns_gui(self, text):
            self.patterns_info.insert(tk.END, text + "\n")
            self.patterns_info.see(tk.END)

        def _log_web_gui(self, text):
            self.web_log.insert(tk.END, text + "\n")
            self.web_log.see(tk.END)

        def _set_backend_gui(self, backend: str):
            self.backend_name = backend
            self.backend_label.config(text=f"Backend: {backend}")
            self.backend_info.config(text=f"Active Backend: {backend}")

        def _set_web_status_gui(self, status: str):
            self.web_status_label.config(text=f"Web Status: {status}")

        def _set_web_url_gui(self, url: str):
            self.web_url_label.config(text=f"Active URL: {url}")

        def _update_chapters_gui(self, text: str):
            self.chapters_list.delete("1.0", tk.END)
            self.chapters_list.insert(tk.END, text)
            self.chapters_list.see(tk.END)

        def _update_graph_gui(self, text: str):
            self.graph_view.delete("1.0", tk.END)
            self.graph_view.insert(tk.END, text)
            self.graph_view.see(tk.END)

        def _update_gpu_heatmap_gui(self, text: str):
            self.gpu_heatmap.delete("1.0", tk.END)
            self.gpu_heatmap.insert(tk.END, text)
            self.gpu_heatmap.see(tk.END)

        def _update_embedding_gui(self, text: str):
            self.embedding_view.delete("1.0", tk.END)
            self.embedding_view.insert(tk.END, text)
            self.embedding_view.see(tk.END)

        def _update_routing_gui(self, text: str):
            self.routing_view.delete("1.0", tk.END)
            self.routing_view.insert(tk.END, text)
            self.routing_view.see(tk.END)

        def _update_timeline_gui(self, text: str):
            self.timeline_view.delete("1.0", tk.END)
            self.timeline_view.insert(tk.END, text)
            self.timeline_view.see(tk.END)

        def _update_routing_heatmap_gui(self, text: str):
            self.routing_heatmap_view.delete("1.0", tk.END)
            self.routing_heatmap_view.insert(tk.END, text)
            self.routing_heatmap_view.see(tk.END)

        def _reload_backend_gui(self):
            self._log_gui("[SYSTEM] Backend reload requested")
            self._set_active_gui(True)
            time.sleep(1)
            self._set_active_gui(False)

        def _reload_backend_safe(self):
            threading.Thread(target=self._reload_backend_gui, daemon=True).start()

        def _search_chapters_gui(self):
            query = self.search_entry.get().strip().lower()
            if not query or not self._chapters_cache_json:
                self.chapters_list.delete("1.0", tk.END)
                self.chapters_list.insert(tk.END, self._chapters_cache_text)
                return

            lines = []
            for cid, ch in self._chapters_cache_json.items():
                title = ch.get("title", "")
                summary = ch.get("summary", "")
                if query in title.lower() or query in summary.lower():
                    lines.append(f"[{cid}] {title}\n{summary}\n")

            if not lines:
                lines.append("No chapters matched search.\n")

            self.chapters_list.delete("1.0", tk.END)
            self.chapters_list.insert(tk.END, "\n".join(lines))
            self.chapters_list.see(tk.END)

        def _search_chapters_safe(self):
            self._enqueue(self._search_chapters_gui)

        def _generate_plot_pca_gui(self):
            if matplotlib is None:
                self.plot_status_label.config(text="Embedding Plot: matplotlib not available")
                return
            if self._embedding_cache is None or self._embedding_cache.shape[0] == 0:
                self.plot_status_label.config(text="Embedding Plot: no embeddings cached")
                return

            try:
                pca = PCA(n_components=2)
                reduced = pca.fit_transform(self._embedding_cache)
                plt.figure(figsize=(6, 6))
                xs = reduced[:, 0]
                ys = reduced[:, 1]
                plt.scatter(xs, ys, s=10, alpha=0.7)
                plt.title("Embedding PCA Plot")
                plt.xlabel("PC1")
                plt.ylabel("PC2")
                plt.tight_layout()
                plt.show()
                self.plot_status_label.config(text="Embedding Plot: PCA generated")
            except Exception as e:
                self.plot_status_label.config(text=f"Embedding Plot: PCA error {e}")

        def _generate_plot_pca_safe(self):
            self._enqueue(self._generate_plot_pca_gui)

        def _generate_plot_umap_gui(self):
            if matplotlib is None or umap is None:
                self.plot_status_label.config(text="Embedding Plot: UMAP not available")
                return
            if self._embedding_cache is None or self._embedding_cache.shape[0] == 0:
                self.plot_status_label.config(text="Embedding Plot: no embeddings cached")
                return

            try:
                reducer = umap.UMAP(n_components=2, random_state=42)
                reduced = reducer.fit_transform(self._embedding_cache)
                plt.figure(figsize=(6, 6))
                xs = reduced[:, 0]
                ys = reduced[:, 1]
                plt.scatter(xs, ys, s=10, alpha=0.7)
                plt.title("Embedding UMAP Plot")
                plt.xlabel("UMAP1")
                plt.ylabel("UMAP2")
                plt.tight_layout()
                plt.show()
                self.plot_status_label.config(text="Embedding Plot: UMAP generated")
            except Exception as e:
                self.plot_status_label.config(text=f"Embedding Plot: UMAP error {e}")

        def _generate_plot_umap_safe(self):
            self._enqueue(self._generate_plot_umap_gui)

        def _stats_loop(self):
            while self.running:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent

                self._enqueue(self.cpu_label.config, text=f"CPU: {cpu}%")
                self._enqueue(self.ram_label.config, text=f"RAM: {ram}%")

                gpu_text = "GPU: Not available"
                heatmap_text = ""
                if torch.cuda.is_available():
                    try:
                        gpu_mem = torch.cuda.memory_allocated() / (1024 ** 2)
                        gpu_text = f"GPU: {gpu_mem:.1f} MB used"
                        bars = int(min(50, gpu_mem / 10))
                        heatmap_text = "[" + "#" * bars + "-" * (50 - bars) + "]"
                    except Exception:
                        gpu_text = "GPU: Available"
                        heatmap_text = "[GPU info error]"
                self._enqueue(self.gpu_label.config, text=gpu_text)
                self.update_gpu_heatmap(heatmap_text)

                time.sleep(1)

        def _auto_hide_loop(self):
            while self.running:
                idle_time = time.time() - self.last_activity
                if not self.keep_awake_flag:
                    if idle_time > 10 and not self.active:
                        self._enqueue(self.root.withdraw)
                time.sleep(1)

        def _graph_animation_loop(self):
            while self.running:
                if self._graph_text_cache:
                    lines = self._graph_text_cache.splitlines()
                    animated = []
                    t = int(time.time()) % max(1, len(lines))
                    for i, line in enumerate(lines):
                        if i == t:
                            animated.append(">> " + line)
                        else:
                            animated.append("   " + line)
                    self._enqueue(self._update_graph_gui, "\n".join(animated))
                time.sleep(2)

        def start(self):
            self.root.mainloop()

# =========================
# WEB ACTIVITY MONITOR
# =========================

class WebActivityMonitor:
    def __init__(self, cockpit: Optional[LLMCockpitGUI], analysis_callback=None, correlation_callback=None, auto_tag_callback=None, refine_callback=None):
        self.cockpit = cockpit
        self.running = True
        self.analysis_callback = analysis_callback
        self.correlation_callback = correlation_callback
        self.auto_tag_callback = auto_tag_callback
        self.refine_callback = refine_callback
        self.last_url = None

    def get_active_url_from_file(self) -> Optional[str]:
        try:
            if os.path.exists("active_url.txt"):
                with open("active_url.txt", "r", encoding="utf-8") as f:
                    url = f.read().strip()
                    return url if url else None
        except:
            return None
        return None

    def get_extension_payload(self) -> Optional[Dict[str, Any]]:
        try:
            if os.path.exists("extension_payload.json"):
                with open("extension_payload.json", "r", encoding="utf-8") as f:
                    return json.load(f)
        except:
            return None
        return None

    def get_active_url(self) -> Optional[str]:
        return self.get_active_url_from_file()

    def run(self):
        if self.cockpit:
            self.cockpit.log_web("[WEB] WebActivityMonitor started.")
            self.cockpit.set_web_status("Monitoring")

        while self.running:
            url = self.get_active_url()
            payload = self.get_extension_payload()
            if url and self.cockpit:
                if url != self.last_url:
                    self.last_url = url
                    self.cockpit.keep_awake()
                    self.cockpit.set_web_url(url)
                    self.cockpit.log_web(f"[WEB] Active URL: {url}")

                    if payload:
                        self.cockpit.log_web(f"[WEB] Extension payload: {payload}")

                    if self.analysis_callback:
                        try:
                            self.analysis_callback(url, payload)
                        except Exception as e:
                            self.cockpit.log_web(f"[WEB] Analysis error: {e}")

                    if self.correlation_callback:
                        try:
                            self.correlation_callback(url, payload)
                        except Exception as e:
                            self.cockpit.log_web(f"[WEB] Correlation error: {e}")

                    if self.auto_tag_callback:
                        try:
                            self.auto_tag_callback(url, payload)
                        except Exception as e:
                            self.cockpit.log_web(f"[WEB] Auto-tag error: {e}")

                    if self.refine_callback:
                        try:
                            self.refine_callback(url, payload)
                        except Exception as e:
                            self.cockpit.log_web(f"[WEB] Refinement error: {e}")
            time.sleep(2)

# =========================
# KNOWLEDGE GRAPH
# =========================

class KnowledgeGraph:
    def __init__(self, path: str, timeline_path: str = "chapter_timeline.json"):
        self.path = path
        self.timeline_path = timeline_path
        self.graph: Dict[str, Any] = {"nodes": {}, "edges": []}
        self.timeline: Dict[str, List[Dict[str, Any]]] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.graph = json.load(f)
            except Exception:
                self.graph = {"nodes": {}, "edges": []}
        if os.path.exists(self.timeline_path):
            try:
                with open(self.timeline_path, "r", encoding="utf-8") as f:
                    self.timeline = json.load(f)
            except Exception:
                self.timeline = {}

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.graph, f, indent=2, ensure_ascii=False)
        with open(self.timeline_path, "w", encoding="utf-8") as f:
            json.dump(self.timeline, f, indent=2, ensure_ascii=False)

    def add_chapter(self, chapter_id: str, title: str, summary: str, topic_seed: str, tags: List[str]):
        self.graph["nodes"][chapter_id] = {
            "title": title,
            "summary": summary,
            "topic_seed": topic_seed,
            "tags": tags,
        }
        self._append_timeline(chapter_id, "create", title, summary, tags)

    def refine_chapter(self, chapter_id: str, new_summary: str, new_tags: List[str]):
        if chapter_id in self.graph["nodes"]:
            old = self.graph["nodes"][chapter_id]
            self.graph["nodes"][chapter_id]["summary"] = new_summary
            self.graph["nodes"][chapter_id]["tags"] = list(sorted(set(new_tags)))
            self._append_timeline(chapter_id, "refine", old.get("title", ""), new_summary, new_tags)

    def add_edge(self, src: str, dst: str, relation: str):
        self.graph["edges"].append({"src": src, "dst": dst, "relation": relation})

    def build_relations_from_chapters(self, chapters: Dict[str, Any]):
        labels = list(chapters.keys())
        for i in range(len(labels)):
            for j in range(i + 1, len(labels)):
                l1, l2 = labels[i], labels[j]
                t1 = chapters[l1].get("title", "")
                t2 = chapters[l2].get("title", "")
                if any(word in t2.lower() for word in t1.lower().split()):
                    self.add_edge(l1, l2, "related")

    def merge_similar_chapters(self, chapters: Dict[str, Any], threshold: float = 0.7):
        labels = list(chapters.keys())
        merged: Dict[str, Any] = {}
        used = set()

        for i in range(len(labels)):
            li = labels[i]
            if li in used:
                continue

            base = li
            merged[base] = chapters[base]

            t1 = chapters[base]["title"].lower().split()

            for j in range(i + 1, len(labels)):
                lj = labels[j]
                if lj in used:
                    continue

                t2 = chapters[lj]["title"].lower().split()

                overlap = len(set(t1) & set(t2)) / max(1, len(set(t1) | set(t2)))
                if overlap >= threshold:
                    merged[base]["examples"].extend(chapters[lj]["examples"])
                    used.add(lj)

        return merged

    def split_large_chapters(self, chapters: Dict[str, Any], max_examples: int = 50) -> Dict[str, Any]:
        new_chapters = {}
        for cid, ch in chapters.items():
            examples = ch.get("examples", [])
            if len(examples) <= max_examples:
                new_chapters[cid] = ch
                continue
            chunks = [examples[i:i+max_examples] for i in range(0, len(examples), max_examples)]
            for idx, chunk in enumerate(chunks):
                new_id = f"{cid}_part{idx+1}"
                new_chapters[new_id] = {
                    **ch,
                    "examples": chunk,
                    "title": f"{ch['title']} (part {idx+1})",
                }
        return new_chapters

    def prune_semantic(self, chapters: Dict[str, Any], min_examples: int = 2) -> Dict[str, Any]:
        pruned = {}
        for cid, ch in chapters.items():
            if len(ch.get("examples", [])) >= min_examples:
                pruned[cid] = ch
        return pruned

    def neighbors(self, chapter_id: str) -> List[str]:
        return [e["dst"] for e in self.graph["edges"] if e["src"] == chapter_id]

    def _append_timeline(self, chapter_id: str, event_type: str, title: str, summary: str, tags: List[str]):
        if chapter_id not in self.timeline:
            self.timeline[chapter_id] = []
        self.timeline[chapter_id].append({
            "time": time.time(),
            "event": event_type,
            "title": title,
            "summary": summary,
            "tags": tags,
        })

    def timeline_text(self) -> str:
        lines = []
        for cid, events in self.timeline.items():
            lines.append(f"Chapter {cid}:")
            for e in events:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["time"]))
                lines.append(f"  [{ts}] {e['event']} title={e['title']} tags={e['tags']}")
        return "\n".join(lines)

    def to_text(self) -> str:
        lines = []
        lines.append("Nodes:")
        for cid, data in self.graph["nodes"].items():
            lines.append(f"  {cid}: {data['title']} ({data.get('topic_seed','')}) tags={data.get('tags', [])}")
        lines.append("\nEdges:")
        for e in self.graph["edges"]:
            lines.append(f"  {e['src']} -> {e['dst']} [{e['relation']}]")
        return "\n".join(lines)

# =========================
# LLM DISSECTOR + CHAPTER LAYER
# =========================

def auto_tags_from_title(title: str) -> List[str]:
    words = [w.strip(".,!?").lower() for w in title.split()]
    return [w for w in words if len(w) > 3]

def build_chapters_from_index(index: Dict[str, Any], llm_generate) -> Dict[str, Any]:
    chapters = {}
    for label, data in index.items():
        examples = data["examples"]
        topic_seeds = list({e["topic_seed"] for e in examples})
        seed_text = ", ".join(topic_seeds)
        sample_qas = "\n".join(
            [f"Q: {e['question']}\nA: {e['answer']}" for e in examples[:3]]
        )
        prompt = (
            "You are summarizing a cluster of Q&A pairs.\n\n"
            f"Topic seeds: {seed_text}\n\n"
            f"{sample_qas}\n\n"
            "Generate a short, clear title and a 1-2 sentence summary.\n"
            "Format:\nTitle: <title>\nSummary: <summary>"
        )
        try:
            resp = llm_generate(prompt)
            title = "Chapter " + label
            summary = "Auto-generated topic cluster"
            for line in resp.splitlines():
                if line.lower().startswith("title:"):
                    title = line.split(":", 1)[1].strip()
                elif line.lower().startswith("summary:"):
                    summary = line.split(":", 1)[1].strip()
        except Exception:
            title = "Chapter " + label
            summary = "Auto-generated topic cluster"

        tags = auto_tags_from_title(title)

        chapters[label] = {
            "title": title,
            "summary": summary,
            "centroid": data["centroid"],
            "examples": examples,
            "topic_seeds": topic_seeds,
            "subtopics": [],
            "tags": tags,
        }
    return chapters

class EmbeddingCacheTTL:
    def __init__(self, ttl: float = 300.0, max_items: int = 1000):
        self.ttl = ttl
        self.max_items = max_items
        self.cache: Dict[str, Tuple[float, np.ndarray]] = {}

    def get(self, key: str) -> Optional[np.ndarray]:
        entry = self.cache.get(key)
        if not entry:
            return None
        ts, emb = entry
        if time.time() - ts > self.ttl:
            self.cache.pop(key, None)
            return None
        return emb

    def set(self, key: str, emb: np.ndarray):
        self.cache[key] = (time.time(), emb)
        if len(self.cache) > self.max_items:
            k = next(iter(self.cache.keys()))
            self.cache.pop(k, None)

class RetrievalCache:
    def __init__(self, max_items: int = 100):
        self.max_items = max_items
        self.cache: Dict[str, Any] = {}

    def get(self, key: str) -> Optional[Any]:
        return self.cache.get(key)

    def set(self, key: str, value: Any):
        self.cache[key] = value
        if len(self.cache) > self.max_items:
            k = next(iter(self.cache.keys()))
            self.cache.pop(k, None)

class AsyncBatcher:
    def __init__(self, infer_fn, max_batch_size: int = 4, flush_interval: float = 0.2):
        self.infer_fn = infer_fn
        self.max_batch_size = max_batch_size
        self.flush_interval = flush_interval
        self.queue: List[Tuple[str, Dict[str, Any], queue.Queue]] = []
        self.lock = threading.Lock()
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            time.sleep(self.flush_interval)
            self._flush()

    def _flush(self):
        with self.lock:
            if not self.queue:
                return
            batch = self.queue[:self.max_batch_size]
            self.queue = self.queue[self.max_batch_size:]
        prompts = [item[0] for item in batch]
        configs = [item[1] for item in batch]
        outs = []
        for p, cfg in zip(prompts, configs):
            # FIX: no duplicate max_new_tokens; cfg already contains it
            out = self.infer_fn(p, **cfg)
            outs.append(out)
        for (_, _, q), o in zip(batch, outs):
            q.put(o)

    def submit(self, prompt: str, config: Dict[str, Any]) -> str:
        result_q = queue.Queue()
        with self.lock:
            self.queue.append((prompt, config, result_q))
        return result_q.get()

class LLMDissector:
    def __init__(
        self,
        model_id: str = None,
        embed_model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        embed_model_name_secondary: str = "sentence-transformers/all-mpnet-base-v2",
        index_path: str = None,
        pattern_path: str = None,
        cockpit: Any = None,
        graph_path: str = "knowledge_graph.json",
        timeline_path: str = "chapter_timeline.json",
    ):
        self.llm_loader = LocalLLM_AutoLoader()
        self.infer, self.backend, self.model = self.llm_loader.load(model_id)

        safe_name = (model_id or f"local_{self.backend}").replace("/", "_")
        self.index_path = index_path or f"{safe_name}_index.json"
        self.chapters_path = f"{safe_name}_chapters.json"
        self.pattern_path = pattern_path or f"{safe_name}_patterns.npy"

        self.embed_model_primary = SentenceTransformer(embed_model_name)
        self.embed_model_secondary = SentenceTransformer(embed_model_name_secondary)
        self.embed_cache = EmbeddingCacheTTL(ttl=300.0, max_items=2000)

        self.beast = BeastModeCPU(reserve_cores=2)

        self.quant = QuantizationManager(cockpit)
        self.model = self.quant.apply(self.backend, self.model)

        self.activation_recorder = ActivationRecorder() if self.model is not None else None
        if self.model is not None and hasattr(self.model, "lm_head"):
            self.activation_recorder.hook_layer(self.model.lm_head)

        self.llm_name = model_id or f"local_{self.backend}"
        self.cockpit = cockpit

        self.graph = KnowledgeGraph(graph_path, timeline_path=timeline_path)
        self.cache = RetrievalCache()
        self.memory = ContextMemory()

        self.adaptive_weights = {
            "base": 0.7,
            "tags": 0.25,
            "recency": 0.05,
        }

        self.async_batcher = AsyncBatcher(self.infer)

        if self.cockpit is not None:
            self.cockpit.log(f"[INIT] Dissector for {self.llm_name} using backend {self.backend}")
            self.cockpit.set_backend(self.backend)
            self.cockpit.keep_awake()

    def generate(self, prompt: str, max_new_tokens: int = None, config: Dict[str, Any] = None, use_async: bool = True) -> str:
        if max_new_tokens is None:
            max_new_tokens = DEFAULT_INFERENCE_CONFIG["max_new_tokens"]
        cfg = DEFAULT_INFERENCE_CONFIG.copy()
        if config:
            cfg.update(config)
        cfg["max_new_tokens"] = max_new_tokens

        if self.cockpit is not None:
            self.cockpit.set_active(True)
            self.cockpit.log(f"[INFER] {prompt}")

        if use_async:
            out = self.async_batcher.submit(prompt, cfg)
        else:
            out = self.infer(
                prompt,
                max_new_tokens=max_new_tokens,
                temperature=cfg["temperature"],
                top_k=cfg["top_k"],
                top_p=cfg["top_p"],
            )

        if self.cockpit is not None:
            self.cockpit.log(f"[OUT] {out}")
            self.cockpit.set_active(False)
        return out

    def rewrite_query(self, question: str) -> str:
        prompt = DEFAULT_PROMPT_TEMPLATES["rewrite"].format(question=question)
        try:
            return self.generate(prompt, max_new_tokens=128)
        except Exception:
            return question

    def decompose_query(self, question: str) -> List[str]:
        prompt = DEFAULT_PROMPT_TEMPLATES["decompose"].format(question=question)
        try:
            resp = self.generate(prompt, max_new_tokens=256)
            subs = []
            for line in resp.splitlines():
                line = line.strip()
                if line.startswith("-") or line.startswith("*"):
                    subs.append(line.lstrip("-* ").strip())
            return subs if subs else [question]
        except Exception:
            return [question]

    def _embed_text(self, text: str) -> np.ndarray:
        cached = self.embed_cache.get(text)
        if cached is not None:
            return cached
        e1 = self.embed_model_primary.encode([text], convert_to_numpy=True)[0]
        e2 = self.embed_model_secondary.encode([text], convert_to_numpy=True)[0]
        emb = np.concatenate([e1, e2]).astype(np.float32)
        self.embed_cache.set(text, emb)
        return emb

    def dissect(
        self,
        topic_prompts: Dict[str, List[str]],
        n_clusters: int = 32,
        record_patterns: bool = False,
    ) -> Dict[str, Any]:
        self.beast.apply()
        if self.activation_recorder:
            self.activation_recorder.clear()

        all_texts: List[str] = []
        meta: List[Dict[str, Any]] = []

        for topic_seed, prompts in topic_prompts.items():
            for q in prompts:
                a = self.generate(q)
                combined = f"Q: {q}\nA: {a}"
                all_texts.append(combined)
                meta.append(
                    {
                        "topic_seed": topic_seed,
                        "question": q,
                        "answer": a,
                    }
                )

        embeddings = np.stack([self._embed_text(t) for t in all_texts], axis=0)

        num_samples = embeddings.shape[0]
        if num_samples == 0:
            if self.cockpit is not None:
                self.cockpit.log("[DISSECT] No samples to cluster.")
            return {}

        if n_clusters > num_samples:
            if self.cockpit is not None:
                self.cockpit.log(f"[DISSECT] Adjusting clusters from {n_clusters} to {num_samples}")
            n_clusters = num_samples

        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        labels = kmeans.fit_predict(embeddings)

        index: Dict[str, Any] = {}
        for i, label in enumerate(labels):
            label_str = str(label)
            if label_str not in index:
                index[label_str] = {
                    "examples": [],
                    "centroid": kmeans.cluster_centers_[label].tolist(),
                }
            index[label_str]["examples"].append(meta[i])

        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

        chapters = build_chapters_from_index(index, self.generate)
        merged_chapters = self.graph.merge_similar_chapters(chapters, threshold=0.7)
        evolved_chapters = self.graph.split_large_chapters(merged_chapters, max_examples=50)
        pruned_chapters = self.graph.prune_semantic(evolved_chapters, min_examples=2)

        with open(self.chapters_path, "w", encoding="utf-8") as f:
            json.dump(pruned_chapters, f, indent=2, ensure_ascii=False)

        for cid, ch in pruned_chapters.items():
            topic_seed = ", ".join(ch.get("topic_seeds", []))
            self.graph.add_chapter(cid, ch["title"], ch["summary"], topic_seed, ch.get("tags", []))
        self.graph.build_relations_from_chapters(pruned_chapters)
        self.graph.save()

        if self.cockpit is not None:
            self.cockpit.update_chapters_view(
                json.dumps(pruned_chapters, indent=2, ensure_ascii=False),
                pruned_chapters,
            )
            self.cockpit.update_graph_view(self.graph.to_text())
            self.cockpit.update_embedding_view(
                "\n".join(
                    [f"{i}: {meta[i]['topic_seed']}" for i in range(len(meta))]
                ),
                embeddings=embeddings,
                meta=meta,
            )
            self.cockpit.update_timeline_view(self.graph.timeline_text())

        if record_patterns and self.activation_recorder is not None:
            pattern_matrix = self.activation_recorder.get_matrix()
            np.save(self.pattern_path, pattern_matrix)
            if self.cockpit is not None:
                self.cockpit.log_patterns(f"[PATTERNS] Saved {pattern_matrix.shape} for {self.llm_name}")

        return pruned_chapters

    def load_chapters(self) -> Dict[str, Any]:
        if not os.path.exists(self.chapters_path):
            raise FileNotFoundError(f"Chapters file not found: {self.chapters_path}")
        with open(self.chapters_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_patterns(self) -> np.ndarray:
        if not os.path.exists(self.pattern_path):
            return np.zeros((0, 0), dtype=np.float32)
        return np.load(self.pattern_path)

    def _cosine_sim(self, v1: np.ndarray, v2: np.ndarray) -> float:
        num = np.dot(v1, v2)
        den = np.linalg.norm(v1) * np.linalg.norm(v2)
        if den == 0:
            return 0.0
        return float(num / den)

    def _update_adaptive_weights(self, success: bool):
        if success:
            self.adaptive_weights["base"] = min(0.85, self.adaptive_weights["base"] + 0.01)
            self.adaptive_weights["tags"] = max(0.15, self.adaptive_weights["tags"] - 0.005)
        else:
            self.adaptive_weights["base"] = max(0.6, self.adaptive_weights["base"] - 0.01)
            self.adaptive_weights["tags"] = min(0.3, self.adaptive_weights["tags"] + 0.005)

    def weighted_route_to_chapter(self, question: str, chapters: Dict[str, Any]) -> Tuple[Optional[str], float, str]:
        cache_key = f"route::{question}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        q_emb = self._embed_text(question)
        recent_tags = self.memory.recent_tags()
        recent_chapters = self.memory.recent_chapters()

        best_label = None
        best_score = -1.0
        routing_log_lines = []

        for label, ch in chapters.items():
            centroid = np.array(ch["centroid"], dtype=np.float32)
            base_score = self._cosine_sim(q_emb, centroid)

            tag_score = 0.0
            if recent_tags:
                overlap = len(set(ch.get("tags", []) & set(recent_tags)))
                tag_score = overlap / max(1, len(set(ch.get("tags", [])) | set(recent_tags)))

            recency_bonus = 0.0
            if label in recent_chapters:
                recency_bonus = 0.05

            score = (
                self.adaptive_weights["base"] * base_score
                + self.adaptive_weights["tags"] * tag_score
                + self.adaptive_weights["recency"] * recency_bonus
            )
            routing_log_lines.append(
                f"[ROUTE] {label}: base={base_score:.3f}, tags={tag_score:.3f}, recency={recency_bonus:.3f}, total={score:.3f}"
            )

            if score > best_score:
                best_score = score
                best_label = label

        routing_log = "\n".join(routing_log_lines)
        self.cache.set(cache_key, (best_label, best_score, routing_log))
        if self.cockpit is not None:
            heatmap = "\n".join(
                [l.replace("[ROUTE]", "").strip() for l in routing_log_lines]
            )
            self.cockpit.update_routing_heatmap(heatmap)
        return best_label, best_score, routing_log

    def graph_based_routing(self, question: str, chapters: Dict[str, Any]) -> Tuple[Optional[str], float, str]:
        label, score, base_log = self.weighted_route_to_chapter(question, chapters)
        if label is None:
            return None, 0.0, base_log

        neighbors = self.graph.neighbors(label)
        q_emb = self._embed_text(question)
        best_label = label
        best_score = score
        log_lines = [base_log, "[GRAPH_ROUTE] exploring neighbors: " + ", ".join(neighbors)]

        for n in neighbors:
            if n not in chapters:
                continue
            centroid = np.array(chapters[n]["centroid"], dtype=np.float32)
            s = self._cosine_sim(q_emb, centroid)
            log_lines.append(f"[GRAPH_ROUTE] neighbor {n}: score={s:.3f}")
            if s > best_score:
                best_score = s
                best_label = n

        routing_log = "\n".join(log_lines)
        if self.cockpit is not None:
            self.cockpit.update_routing_view(routing_log)
        return best_label, best_score, routing_log

    def semantic_search(self, query: str, chapters: Dict[str, Any], top_k: int = 5) -> List[Tuple[str, float]]:
        q_emb = self._embed_text(query)
        scores = []
        for label, ch in chapters.items():
            centroid = np.array(ch["centroid"], dtype=np.float32)
            score = self._cosine_sim(q_emb, centroid)
            scores.append((label, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]

    def multi_hop_recursive_retrieval(self, question: str, chapters: Dict[str, Any], max_hops: int = 3) -> Dict[str, Any]:
        label, score, routing_log = self.graph_based_routing(question, chapters)
        if label is None:
            return {"label": None, "score": 0.0, "context": "", "routing_log": routing_log}

        visited = set()
        context_parts = []
        current_label = label

        for hop in range(max_hops):
            if current_label in visited:
                break
            visited.add(current_label)
            ch = chapters[current_label]
            for e in ch["examples"][:3]:
                context_parts.append(f"[HOP {hop}] Q: {e['question']}\nA: {e['answer']}")
            neighbors = self.graph.neighbors(current_label)
            if not neighbors:
                break
            q_emb = self._embed_text(question)
            best_neighbor = None
            best_neighbor_score = -1.0
            for n in neighbors:
                if n not in chapters:
                    continue
                centroid = np.array(chapters[n]["centroid"], dtype=np.float32)
                s = self._cosine_sim(q_emb, centroid)
                if s > best_neighbor_score:
                    best_neighbor_score = s
                    best_neighbor = n
            if best_neighbor is None or best_neighbor_score < 0.2:
                break
            current_label = best_neighbor

        context = "\n\n".join(context_parts)
        return {"label": label, "score": score, "context": context, "routing_log": routing_log}

    def explain_answer(self, question: str, answer: str) -> str:
        prompt = DEFAULT_PROMPT_TEMPLATES["explain"].format(question=question, answer=answer)
        try:
            return self.generate(prompt, max_new_tokens=256)
        except Exception:
            return "Explanation mode failed; using direct answer only."

    def detect_semantic_drift(self, chapter_id: str, old_summary: str, new_summary: str, examples: List[Dict[str, Any]]) -> str:
        sample_qas = "\n".join(
            [f"Q: {e['question']}\nA: {e['answer']}" for e in examples[:5]]
        )
        prompt = DEFAULT_PROMPT_TEMPLATES["drift_detect"].format(
            old_summary=old_summary,
            new_summary=new_summary,
            qas=sample_qas,
        )
        try:
            resp = self.generate(prompt, max_new_tokens=256)
            return resp
        except Exception:
            return "DRIFT: unknown\nReason: detection failed"

    def auto_correct_drift(self, chapter_id: str, drift_report: str, chapters: Dict[str, Any]):
        ch = chapters.get(chapter_id)
        if not ch:
            return
        if "DRIFT: yes" not in drift_report.lower():
            return
        prompt = (
            "You are correcting semantic drift in a chapter.\n\n"
            f"Title: {ch['title']}\n"
            f"Current summary: {ch['summary']}\n\n"
            f"Drift report:\n{drift_report}\n\n"
            "Generate a corrected summary (1-2 sentences) that restores the original intent.\n"
            "Format:\nSummary: <summary>"
        )
        try:
            resp = self.generate(prompt, max_new_tokens=256)
            new_summary = ch["summary"]
            for line in resp.splitlines():
                if line.lower().startswith("summary:"):
                    new_summary = line.split(":", 1)[1].strip()
            ch["summary"] = new_summary
            self.graph.refine_chapter(chapter_id, new_summary, ch.get("tags", []))
            self.graph.save()
            if self.cockpit is not None:
                self.cockpit.update_timeline_view(self.graph.timeline_text())
        except Exception:
            pass

    def refine_chapter_over_time(self, chapter_id: str, chapters: Dict[str, Any]):
        ch = chapters.get(chapter_id)
        if not ch:
            return

        examples = ch.get("examples", [])
        if not examples:
            return

        old_summary = ch["summary"]
        sample_qas = "\n".join(
            [f"Q: {e['question']}\nA: {e['answer']}" for e in examples[:5]]
        )
        prompt = (
            "You are refining a chapter summary based on new Q&A examples.\n\n"
            f"Current title: {ch['title']}\n"
            f"Current summary: {ch['summary']}\n\n"
            f"Recent Q&A:\n{sample_qas}\n\n"
            "Generate an improved summary (1-2 sentences) and list 3-7 tags.\n"
            "Format:\nSummary: <summary>\nTags: tag1, tag2, tag3..."
        )
        try:
            resp = self.generate(prompt, max_new_tokens=256)
            new_summary = ch["summary"]
            new_tags = ch.get("tags", [])
            for line in resp.splitlines():
                if line.lower().startswith("summary:"):
                    new_summary = line.split(":", 1)[1].strip()
                elif line.lower().startswith("tags:"):
                    tags_str = line.split(":", 1)[1].strip()
                    new_tags = [t.strip().lower() for t in tags_str.split(",") if t.strip()]
            drift_report = self.detect_semantic_drift(chapter_id, old_summary, new_summary, examples)
            if self.cockpit is not None:
                self.cockpit.log_patterns(f"[DRIFT] {chapter_id}: {drift_report}")

            ch["summary"] = new_summary
            ch["tags"] = new_tags
            self.graph.refine_chapter(chapter_id, new_summary, new_tags)
            self.graph.save()
            if self.cockpit is not None:
                self.cockpit.update_timeline_view(self.graph.timeline_text())

            self.auto_correct_drift(chapter_id, drift_report, chapters)
        except Exception:
            pass

    def self_consistency_score(self, question: str, answer: str) -> float:
        prompt = DEFAULT_PROMPT_TEMPLATES["self_consistency"].format(question=question, answer=answer)
        try:
            resp = self.generate(prompt, max_new_tokens=64)
            for line in resp.splitlines():
                line = line.strip()
                if line.lower().startswith("score:"):
                    val = line.split(":", 1)[1].strip()
                    try:
                        return float(val)
                    except:
                        continue
        except Exception:
            pass
        return 0.0

    def multi_agent_reasoning(self, question: str, chapters: Dict[str, Any]) -> Tuple[str, float]:
        ans1, conf1 = self.answer_with_chapters_single_agent(question, chapters)
        ans2, conf2 = self.answer_with_chapters_single_agent(question, chapters)

        score1 = self.self_consistency_score(question, ans1)
        score2 = self.self_consistency_score(question, ans2)

        weights = [score1, score2]
        total = sum(weights) if sum(weights) > 0 else 1.0
        w1 = weights[0] / total
        w2 = weights[1] / total

        arb_prompt = (
            "You are an arbitration engine with weighted voting.\n\n"
            f"Question:\n{question}\n\n"
            f"Answer A (weight={w1:.3f}):\n{ans1}\n\n"
            f"Answer B (weight={w2:.3f}):\n{ans2}\n\n"
            "Combine them into a single best answer, respecting the weights.\n"
        )
        arb_answer = self.generate(arb_prompt, max_new_tokens=256)

        final_answer = arb_answer if len(arb_answer.strip()) > 0 else ans1
        final_conf = max(conf1, conf2)
        return final_answer, final_conf

    def answer_with_chapters_single_agent(self, question: str, chapters: Dict[str, Any]) -> Tuple[str, float]:
        rewritten = self.rewrite_query(question)
        hops = self.multi_hop_recursive_retrieval(rewritten, chapters, max_hops=3)

        if self.cockpit is not None:
            self.cockpit.update_routing_view(hops["routing_log"])

        if hops["label"] is None:
            ans = self.generate(
                DEFAULT_PROMPT_TEMPLATES["qa"].format(question=rewritten)
            )
            self.memory.add(question, None, [])
            self._update_adaptive_weights(success=False)
            return ans, 0.0

        ch = chapters[hops["label"]]
        context = hops["context"]

        prompt = DEFAULT_PROMPT_TEMPLATES["chapter_qa"].format(
            chapter_title=ch["title"],
            chapter_summary=ch["summary"],
            context=context,
            question=rewritten,
        )

        ans = self.generate(prompt)
        q_emb = self._embed_text(rewritten)
        centroid = np.array(ch["centroid"], dtype=np.float32)
        conf = self._cosine_sim(q_emb, centroid)

        self.memory.add(question, hops["label"], ch.get("tags", []))
        self.refine_chapter_over_time(hops["label"], chapters)
        self._update_adaptive_weights(success=True if conf > 0.4 else False)
        return ans, conf

    def answer_with_chapters(self, question: str, chapters: Dict[str, Any], use_multi_agent: bool = True, explain: bool = False) -> Tuple[str, float, Optional[str]]:
        if use_multi_agent:
            ans, conf = self.multi_agent_reasoning(question, chapters)
        else:
            ans, conf = self.answer_with_chapters_single_agent(question, chapters)

        explanation = None
        if explain:
            explanation = self.explain_answer(question, ans)

        return ans, conf, explanation

    def cluster_patterns(self, n_clusters: int = 16) -> Dict[str, Any]:
        if self.activation_recorder is None:
            return {"status": "no_torch_model"}

        patterns = self.load_patterns()
        if patterns.size == 0:
            return {"status": "no_patterns_recorded"}

        num_samples = patterns.shape[0]
        if n_clusters > num_samples:
            n_clusters = num_samples

        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        labels = kmeans.fit_predict(patterns)

        cluster_stats = {}
        for c in range(n_clusters):
            mask = labels == c
            if not mask.any():
                continue
            cluster_patterns = patterns[mask]
            mean_vec = cluster_patterns.mean(axis=0)
            var_vec = cluster_patterns.var(axis=0)
            cluster_stats[str(c)] = {
                "count": int(cluster_patterns.shape[0]),
                "mean_sample": mean_vec[:10].tolist(),
                "var_sample": var_vec[:10].tolist(),
            }

        if self.cockpit is not None:
            self.cockpit.log_patterns(f"[CLUSTERS] {self.llm_name}: {cluster_stats}")

        return {
            "status": "ok",
            "num_samples": int(patterns.shape[0]),
            "dim": int(patterns.shape[1]),
            "clusters": cluster_stats,
        }

# =========================
# CROSS-MODEL PATTERN COMPARISON & ENSEMBLE
# =========================

def compare_models_patterns(dissectors: List[LLMDissector]) -> Dict[str, Any]:
    model_names = [d.llm_name for d in dissectors]
    pattern_mats = [d.load_patterns() for d in dissectors]

    valid = [(n, m) for n, m in zip(model_names, pattern_mats) if m.size > 0]
    if len(valid) < 2:
        return {"status": "not_enough_valid_models"}

    names = [v[0] for v in valid]
    mats = [v[1] for v in valid]

    mean_vectors = [m.mean(axis=0) for m in mats]
    mean_matrix = np.stack(mean_vectors, axis=0)

    pca = PCA(n_components=min(32, mean_matrix.shape[1]))
    reduced = pca.fit_transform(mean_matrix)

    def cosine(a, b):
        num = np.dot(a, b)
        den = np.linalg.norm(a) * np.linalg.norm(b)
        if den == 0:
            return 0.0
        return float(num / den)

    similarities = {}
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            s = cosine(reduced[i], reduced[j])
            key = f"{names[i]} vs {names[j]}"
            similarities[key] = s

    return {
        "status": "ok",
        "models": names,
        "similarities": similarities,
    }

def ensemble_answer(question: str, dissectors: List[LLMDissector], explain: bool = False) -> str:
    answers: List[Tuple[str, str, float, Optional[str]]] = []
    for d in dissectors:
        try:
            chapters = d.load_chapters()
            ans, conf, explanation = d.answer_with_chapters(question, chapters, use_multi_agent=True, explain=explain)
            answers.append((d.llm_name, ans, conf, explanation))
        except Exception:
            continue

    if not answers:
        return "No ensemble answers available."

    answers.sort(key=lambda x: x[2], reverse=True)
    combined = []
    for name, ans, conf, explanation in answers:
        block = f"[{name} | confidence={conf:.3f}]\n{ans}"
        if explanation:
            block += f"\n\n[EXPLANATION]\n{explanation}"
        combined.append(block)
    return "\n\n".join(combined)

# =========================
# MAIN
# =========================

def main():
    topic_prompts = {
        "police": [
            "How do police handle a routine traffic stop?",
            "What are standard police procedures during an arrest?",
        ],
        "cars": [
            "How do I diagnose a misfiring engine?",
            "What are common causes of brake failure?",
        ],
        "fire": [
            "How do firefighters approach a house fire?",
            "What is the safest way to evacuate a burning building?",
        ],
    }

    model_ids = [
        "local_llm_1",
        "local_llm_2",
    ]

    cockpit = None
    if LLMCockpitGUI is not None:
        cockpit = LLMCockpitGUI(backend_name="auto", model_ids=model_ids)

        def web_analysis_callback(url: str, payload: Optional[Dict[str, Any]]):
            cockpit.log_web(f"[WEB] Analyzing URL via LLM: {url}")
            if payload:
                cockpit.log_web(f"[WEB] Payload: {payload}")

        def web_correlation_callback(url: str, payload: Optional[Dict[str, Any]]):
            cockpit.log_web(f"[WEB] Correlating URL with chapters (placeholder): {url}")
            if payload:
                cockpit.log_web(f"[WEB] Correlation payload: {payload}")

        def web_auto_tag_callback(url: str, payload: Optional[Dict[str, Any]]):
            cockpit.log_web(f"[WEB] Auto-tagging chapters based on URL: {url}")

        def web_refine_callback(url: str, payload: Optional[Dict[str, Any]]):
            cockpit.log_web(f"[WEB] Triggering chapter refinement from web context: {url}")

        web_monitor = WebActivityMonitor(
            cockpit,
            analysis_callback=web_analysis_callback,
            correlation_callback=web_correlation_callback,
            auto_tag_callback=web_auto_tag_callback,
            refine_callback=web_refine_callback,
        )
        threading.Thread(target=web_monitor.run, daemon=True).start()

        def run_llm_system():
            cockpit.keep_awake()

            dissectors: List[LLMDissector] = []

            for mid in model_ids:
                d = LLMDissector(model_id=mid, cockpit=cockpit)
                chapters = d.dissect(topic_prompts, n_clusters=8, record_patterns=False)
                stats = d.cluster_patterns(n_clusters=4)
                cockpit.log_patterns(f"[CLUSTER_STATS] {mid}: {stats}")
                dissectors.append(d)

            comparison = compare_models_patterns(dissectors)
            cockpit.log_patterns(f"[COMPARE] {comparison}")

            if dissectors:
                q = "How do police handle domestic disturbance calls?"
                ens = ensemble_answer(q, dissectors, explain=True)
                cockpit.log(f"[Q] {q}")
                cockpit.log(f"[ENSEMBLE_ANSWER]\n{ens}")

                d0 = dissectors[0]
                ch0 = d0.load_chapters()
                results = d0.semantic_search("traffic stop procedure", ch0, top_k=3)
                cockpit.log(f"[SEMANTIC_SEARCH] traffic stop procedure → {results}")

        threading.Thread(target=run_llm_system, daemon=True).start()
        cockpit.start()

    else:
        dissectors: List[LLMDissector] = []
        for mid in model_ids:
            d = LLMDissector(model_id=mid, cockpit=None)
            chapters = d.dissect(topic_prompts, n_clusters=8, record_patterns=False)
            stats = d.cluster_patterns(n_clusters=4)
            print(f"[CLUSTER_STATS] {mid}:", stats)
            dissectors.append(d)

        comparison = compare_models_patterns(dissectors)
        print("[COMPARE]", comparison)

        if dissectors:
            q = "How do police handle domestic disturbance calls?"
            ens = ensemble_answer(q, dissectors, explain=True)
            print("Q:", q)
            print("ENSEMBLE ANSWER:\n", ens)

            d0 = dissectors[0]
            ch0 = d0.load_chapters()
            results = d0.semantic_search("traffic stop procedure", ch0, top_k=3)
            print("[SEMANTIC_SEARCH] traffic stop procedure →", results)


if __name__ == "__main__":
    main()
