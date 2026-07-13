#!/usr/bin/env python3
"""
Unified LLM Dissector System
Local-Only, All Backends Auto-Detect, Copilot Fallback,
Cockpit Ultra Mode + Advanced Quantization + Tkinter Main-Thread Fix
+ Keep-Awake Mode + Full Web Integration + Copilot Backend Fix
+ Stats Loop Fix (kwargs-safe enqueue)

Backends (auto-detected, in this order):
- LM Studio (HTTP server on 127.0.0.1:1234)
- Ollama
- GPT4All (models/ directory)
- GGUF (llama.cpp)
- Local safetensors / HF-style local dir
- Copilot (fallback when no local backend is found)
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
from typing import Dict, List, Any, Optional

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

if None in (np, psutil, torch, transformers, sentence_transformers, sklearn, requests):
    print("[System] Critical modules missing; exiting.")
    sys.exit(1)

from transformers import AutoModelForCausalLM, AutoTokenizer
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

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
    """
    Advanced quantization manager.

    Modes (env vars):
    - QUANT_FP16=1        → FP16
    - QUANT_BF16=1        → BF16 (if supported)
    - QUANT_INT8=1        → dynamic INT8 on Linear (CPU)
    - QUANT_INT8_PERCHAN=1→ intent flag (logged)
    """

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
        def infer(prompt: str, max_new_tokens: int = 256):
            r = requests.post(
                "http://127.0.0.1:1234/v1/chat/completions",
                json={"messages": [{"role": "user", "content": prompt}]}
            )
            j = r.json()
            return j["choices"][0]["message"]["content"]
        return infer

    def wrap_ollama(self):
        def infer(prompt: str, max_new_tokens: int = 256):
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

        def infer(prompt: str, max_new_tokens: int = 256):
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

        def infer(prompt: str, max_new_tokens: int = 256):
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

        def infer(prompt: str, max_new_tokens: int = 256):
            inputs = tokenizer(prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                outputs = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
            return tokenizer.decode(outputs[0], skip_special_tokens=True)

        return infer, model

    def wrap_copilot(self):
        class CopilotFallback:
            def infer(self, prompt: str, max_new_tokens: int = 256):
                return f"[Copilot Fallback Active] {prompt}"

        backend = CopilotFallback()

        def infer(prompt: str, max_new_tokens: int = 256):
            return backend.infer(prompt, max_new_tokens=max_new_tokens)

        return infer

# =========================
# COCKPIT ULTRA GUI (Tkinter main-thread, kwargs-safe enqueue)
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
            self.root.geometry("1200x750")
            self.root.resizable(False, False)
            self.root.withdraw()

            self.tabs = ttk.Notebook(self.root)
            self.tabs.pack(fill="both", expand=True)

            self.status_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.status_tab, text="Status")

            self.backend_label = tk.Label(self.status_tab, text=f"Backend: {self.backend_name}", font=("Arial", 16))
            self.backend_label.pack(pady=10)

            self.status_label = tk.Label(self.status_tab, text="Status: Idle", font=("Arial", 14))
            self.status_label.pack(pady=5)

            self.activity_indicator = tk.Label(self.status_tab, text="●", font=("Arial", 40), fg="gray")
            self.activity_indicator.pack(pady=10)

            self.monitor_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.monitor_tab, text="System Monitor")

            self.cpu_label = tk.Label(self.monitor_tab, text="CPU: 0%", font=("Arial", 14))
            self.cpu_label.pack(pady=10)

            self.ram_label = tk.Label(self.monitor_tab, text="RAM: 0%", font=("Arial", 14))
            self.ram_label.pack(pady=10)

            self.gpu_label = tk.Label(self.monitor_tab, text="GPU: N/A", font=("Arial", 14))
            self.gpu_label.pack(pady=10)

            self.console_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.console_tab, text="Inference Console")

            self.console = scrolledtext.ScrolledText(self.console_tab, width=120, height=25, font=("Consolas", 10))
            self.console.pack(pady=10)

            self.backend_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.backend_tab, text="Backend")

            self.backend_info = tk.Label(self.backend_tab, text=f"Active Backend: {self.backend_name}", font=("Arial", 14))
            self.backend_info.pack(pady=10)

            self.reload_button = tk.Button(self.backend_tab, text="Reload Backend", command=self._reload_backend_safe)
            self.reload_button.pack(pady=10)

            self.patterns_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.patterns_tab, text="Patterns")

            self.patterns_info = scrolledtext.ScrolledText(self.patterns_tab, width=120, height=25, font=("Consolas", 10))
            self.patterns_info.pack(pady=10)

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

            self.web_tab = ttk.Frame(self.tabs)
            self.tabs.add(self.web_tab, text="Web")

            self.web_status_label = tk.Label(self.web_tab, text="Web Status: Idle", font=("Arial", 14))
            self.web_status_label.pack(pady=10)

            self.web_url_label = tk.Label(self.web_tab, text="Active URL: (none)", font=("Arial", 12))
            self.web_url_label.pack(pady=5)

            self.web_log = scrolledtext.ScrolledText(self.web_tab, width=120, height=20, font=("Consolas", 10))
            self.web_log.pack(pady=10)

            self.root.after(100, self._process_gui_queue)
            threading.Thread(target=self._stats_loop, daemon=True).start()
            threading.Thread(target=self._auto_hide_loop, daemon=True).start()

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

        def _reload_backend_gui(self):
            self._log_gui("[SYSTEM] Backend reload requested")
            self._set_active_gui(True)
            time.sleep(1)
            self._set_active_gui(False)

        def _reload_backend_safe(self):
            threading.Thread(target=self._reload_backend_gui, daemon=True).start()

        def _stats_loop(self):
            while self.running:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent

                self._enqueue(self.cpu_label.config, text=f"CPU: {cpu}%")
                self._enqueue(self.ram_label.config, text=f"RAM: {ram}%")

                if torch.cuda.is_available():
                    try:
                        gpu_mem = torch.cuda.memory_allocated() / (1024 ** 2)
                        gpu_text = f"GPU: {gpu_mem:.1f} MB used"
                    except Exception:
                        gpu_text = "GPU: Available"
                else:
                    gpu_text = "GPU: Not available"

                self._enqueue(self.gpu_label.config, text=gpu_text)

                time.sleep(1)

        def _auto_hide_loop(self):
            while self.running:
                idle_time = time.time() - self.last_activity
                if not self.keep_awake_flag:
                    if idle_time > 10 and not self.active:
                        self._enqueue(self.root.withdraw)
                time.sleep(1)

        def start(self):
            self.root.mainloop()

# =========================
# WEB ACTIVITY MONITOR
# =========================

class WebActivityMonitor:
    def __init__(self, cockpit: Optional[LLMCockpitGUI], analysis_callback=None):
        self.cockpit = cockpit
        self.running = True
        self.analysis_callback = analysis_callback
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

    def get_active_url(self) -> Optional[str]:
        return self.get_active_url_from_file()

    def run(self):
        if self.cockpit:
            self.cockpit.log_web("[WEB] WebActivityMonitor started.")
            self.cockpit.set_web_status("Monitoring")

        while self.running:
            url = self.get_active_url()
            if url and self.cockpit:
                if url != self.last_url:
                    self.last_url = url
                    self.cockpit.keep_awake()
                    self.cockpit.set_web_url(url)
                    self.cockpit.log_web(f"[WEB] Active URL: {url}")

                    if self.analysis_callback:
                        try:
                            self.analysis_callback(url)
                        except Exception as e:
                            self.cockpit.log_web(f"[WEB] Analysis error: {e}")
            time.sleep(2)

# =========================
# LLM DISSECTOR
# =========================

class LLMDissector:
    def __init__(
        self,
        model_id: str = None,
        embed_model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        index_path: str = None,
        pattern_path: str = None,
        cockpit: Any = None,
    ):
        self.llm_loader = LocalLLM_AutoLoader()
        self.infer, self.backend, self.model = self.llm_loader.load(model_id)

        safe_name = (model_id or f"local_{self.backend}").replace("/", "_")
        self.index_path = index_path or f"{safe_name}_index.json"
        self.pattern_path = pattern_path or f"{safe_name}_patterns.npy"

        self.embed_model = SentenceTransformer(embed_model_name)
        self.beast = BeastModeCPU(reserve_cores=2)

        self.quant = QuantizationManager(cockpit)
        self.model = self.quant.apply(self.backend, self.model)

        self.activation_recorder = ActivationRecorder() if self.model is not None else None
        if self.model is not None and hasattr(self.model, "lm_head"):
            self.activation_recorder.hook_layer(self.model.lm_head)

        self.llm_name = model_id or f"local_{self.backend}"
        self.cockpit = cockpit

        if self.cockpit is not None:
            self.cockpit.log(f"[INIT] Dissector for {self.llm_name} using backend {self.backend}")
            self.cockpit.set_backend(self.backend)
            self.cockpit.keep_awake()

    def generate(self, prompt: str, max_new_tokens: int = 256) -> str:
        if self.cockpit is not None:
            self.cockpit.set_active(True)
            self.cockpit.log(f"[INFER] {prompt}")
        out = self.infer(prompt, max_new_tokens=max_new_tokens)
        if self.cockpit is not None:
            self.cockpit.log(f"[OUT] {out}")
            self.cockpit.set_active(False)
        return out

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

        embeddings = self.embed_model.encode(all_texts, convert_to_numpy=True)

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

        if record_patterns and self.activation_recorder is not None:
            pattern_matrix = self.activation_recorder.get_matrix()
            np.save(self.pattern_path, pattern_matrix)
            if self.cockpit is not None:
                self.cockpit.log_patterns(f"[PATTERNS] Saved {pattern_matrix.shape} for {self.llm_name}")

        return index

    def load_index(self) -> Dict[str, Any]:
        if not os.path.exists(self.index_path):
            raise FileNotFoundError(f"Index file not found: {self.index_path}")
        with open(self.index_path, "r", encoding="utf-8") as f:
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

    def answer_with_index(self, question: str, index: Dict[str, Any]) -> str:
        self.beast.apply()

        q_emb = self.embed_model.encode([question], convert_to_numpy=True)[0]

        best_label = None
        best_score = -1.0

        for label, data in index.items():
            centroid = np.array(data["centroid"], dtype=np.float32)
            score = self._cosine_sim(q_emb, centroid)
            if score > best_score:
                best_score = score
                best_label = label

        if best_label is None:
            return self.generate(question)

        examples = index[best_label]["examples"]
        context_parts = []
        for e in examples[:3]:
            context_parts.append(f"Q: {e['question']}\nA: {e['answer']}")
        context = "\n\n".join(context_parts)

        prompt = (
            context
            + "\n\n---\n\n"
            + f"User: {question}\nAnswer clearly and precisely:"
        )

        return self.generate(prompt)

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
# CROSS-MODEL PATTERN COMPARISON
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

        def web_analysis_callback(url: str):
            cockpit.log_web(f"[WEB] Analyzing URL via LLM: {url}")

        web_monitor = WebActivityMonitor(cockpit, analysis_callback=web_analysis_callback)
        threading.Thread(target=web_monitor.run, daemon=True).start()

        def run_llm_system():
            cockpit.keep_awake()

            dissectors: List[LLMDissector] = []

            for mid in model_ids:
                d = LLMDissector(model_id=mid, cockpit=cockpit)
                d.dissect(topic_prompts, n_clusters=16, record_patterns=False)
                stats = d.cluster_patterns(n_clusters=8)
                cockpit.log_patterns(f"[CLUSTER_STATS] {mid}: {stats}")
                dissectors.append(d)

            comparison = compare_models_patterns(dissectors)
            cockpit.log_patterns(f"[COMPARE] {comparison}")

            if dissectors:
                d0 = dissectors[0]
                index0 = d0.load_index()
                q = "How do police handle domestic disturbance calls?"
                a = d0.answer_with_index(q, index0)
                cockpit.log(f"[Q] {q}")
                cockpit.log(f"[A] {a}")

        threading.Thread(target=run_llm_system, daemon=True).start()
        cockpit.start()

    else:
        dissectors: List[LLMDissector] = []
        for mid in model_ids:
            d = LLMDissector(model_id=mid, cockpit=None)
            d.dissect(topic_prompts, n_clusters=16, record_patterns=False)
            stats = d.cluster_patterns(n_clusters=8)
            print(f"[CLUSTER_STATS] {mid}:", stats)
            dissectors.append(d)

        comparison = compare_models_patterns(dissectors)
        print("[COMPARE]", comparison)

        if dissectors:
            d0 = dissectors[0]
            index0 = d0.load_index()
            q = "How do police handle domestic disturbance calls?"
            a = d0.answer_with_index(q, index0)
            print("Q:", q)
            print("A:", a)


if __name__ == "__main__":
    main()
