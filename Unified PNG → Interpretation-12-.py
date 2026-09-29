#!/usr/bin/env python3
"""
Processor Cube PNG → Blueprint Tool
ULTRA COMMAND CENTER EDITION

Features:
  - Bootloader
  - Autoloader (auto-installs Python libs if missing)
  - Universal path normalizer (drag-and-drop safe)
  - Drag-and-drop + file dialog PNG/JPG recognition
  - Auto-preview of PNG
  - Real-time layer visualization
  - Arrow mini-map
  - GPU-accelerated analyzer (OpenCV CUDA when available)
  - Multi-file batch processor
  - Mode selector (local / hybrid / ai_only)
  - OCR via Tesseract (with detection + instructions if missing)
  - Local AI runtime scanner (Ollama, LM Studio, GPT4All, etc.)
  - LM Studio auto-detection via /v1/models
  - Local model file scanner (.gguf, .ggml, .onnx, .bin, .safetensors, .pth)
  - Internet AI loader (API endpoints, keys, connectivity check)
  - Chat box to talk to the active AI source
  - Send Text → AI
  - Send Image Blueprint → AI (JSON prompt)
  - Send Raw Image → AI (vision models, base64 PNG)
  - Multi-image comparison mode
  - Auto-watchdog mode (folder monitoring + auto-processing)
  - ULTRA Plugin System:
      * PluginManager with event bus
      * Plugin types: analyzer, interpreter, visualizer, exporter, hook
      * Plugin metadata (name, type, priority)
      * Hooks: image_loaded, blueprint_built, ai_request, ai_response,
               blueprint_saved, watchdog_new_file, comparison_done
      * Plugins loaded from ./plugins, hot-load at startup
"""

import importlib
import subprocess
import sys
import os
import json
import threading
import urllib.parse
import io
import socket
import time
import base64
from typing import List, Dict, Any, Optional

# =========================
# AUTOLOADER
# =========================

REQUIRED_LIBS = {
    "cv2": "opencv-python",
    "numpy": "numpy",
    "PIL": "Pillow",
    "pytesseract": "pytesseract",
}

OPTIONAL_AI_LIBS = {
    "requests": "requests",
}

GUI_LIBS = {
    "tkinter": None,
    "tkinter.filedialog": None,
    "tkinter.ttk": None,
    "tkinter.messagebox": None,
    "tkinterdnd2": "tkinterdnd2",
}

def install_package(package_name: str):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

def load_library(module_name: str, package_name: Optional[str] = None):
    try:
        return importlib.import_module(module_name)
    except ImportError:
        if package_name:
            print(f"[AUTOLOADER] Installing missing package: {package_name}")
            install_package(package_name)
            return importlib.import_module(module_name)
        return None

def autoload(all_ai: bool = False) -> Dict[str, Any]:
    libs: Dict[str, Any] = {}
    for m, p in REQUIRED_LIBS.items():
        libs[m] = load_library(m, p)
    if all_ai:
        for m, p in OPTIONAL_AI_LIBS.items():
            libs[m] = load_library(m, p)
    return libs

def load_gui_modules() -> Dict[str, Any]:
    gui_libs: Dict[str, Any] = {}
    for m, p in GUI_LIBS.items():
        gui_libs[m] = load_library(m, p)
    return gui_libs

# =========================
# BOOTLOADER
# =========================

def bootloader_check():
    print("[BOOTLOADER] Checking environment...")
    if sys.version_info < (3, 8):
        print("[BOOTLOADER] Python 3.8+ required.")
        sys.exit(1)

    gui_libs = load_gui_modules()
    if gui_libs.get("tkinter") is None:
        print("[BOOTLOADER] tkinter missing — GUI cannot start.")
        sys.exit(1)

    print("[BOOTLOADER] Boot OK.")

# =========================
# PATH NORMALIZER
# =========================

def normalize_single_path(raw: str) -> str:
    if not raw:
        return ""

    s = raw.strip()
    for ch in ["{", "}", '"', "'"]:
        s = s.replace(ch, "")
    s = s.strip()

    if s.lower().startswith("file://"):
        parsed = urllib.parse.urlparse(s)
        if parsed.netloc and parsed.path:
            unc = f"\\\\{parsed.netloc}{parsed.path}"
            return os.path.normpath(unc)
        elif parsed.path:
            return os.path.normpath(parsed.path)

    return os.path.normpath(s)

def normalize_dropped_data(raw: str) -> List[str]:
    if not raw:
        return []

    raw = raw.strip()
    paths: List[str] = []

    if raw.startswith("{") and raw.endswith("}"):
        segments: List[str] = []
        buf = ""
        depth = 0
        for ch in raw:
            if ch == "{":
                if depth == 0 and buf:
                    segments.append(buf)
                    buf = ""
                depth += 1
            buf += ch
            if ch == "}":
                depth -= 1
                if depth == 0:
                    segments.append(buf)
                    buf = ""
        if buf:
            segments.append(buf)

        if segments:
            for seg in segments:
                seg = seg.strip()
                if seg.startswith("{") and seg.endswith("}"):
                    inner = seg[1:-1]
                else:
                    inner = seg
                inner = inner.strip()
                if inner:
                    p = normalize_single_path(inner)
                    if p:
                        paths.append(p)
        else:
            inner = raw[1:-1].strip()
            if inner:
                p = normalize_single_path(inner)
                if p:
                    paths.append(p)
    else:
        lines = raw.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{") and line.endswith("}"):
                inner = line[1:-1].strip()
                if inner:
                    p = normalize_single_path(inner)
                    if p:
                        paths.append(p)
            else:
                tokens = line.split()
                for token in tokens:
                    p = normalize_single_path(token)
                    if p:
                        paths.append(p)

    seen = set()
    unique: List[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique

# =========================
# ULTRA PLUGIN SYSTEM
# =========================

class PluginManager:
    """
    Ultra plugin system:
      - Loads plugins from ./plugins
      - Each plugin defines a class Plugin with:
          name: str
          type: str (analyzer, interpreter, visualizer, exporter, hook)
          priority: int (lower = earlier)
          hooks: List[str] (event names)
          methods corresponding to hooks, e.g. on_image_loaded(...)
      - Event bus:
          emit(event_name, **kwargs)
    """

    def __init__(self):
        self.plugins: List[Any] = []
        self.hooks: Dict[str, List[Any]] = {}

    def load_plugins(self, plugins_dir: str = "plugins"):
        if not os.path.isdir(plugins_dir):
            print(f"[PLUGIN] No plugins directory found at: {plugins_dir}")
            return

        sys.path.insert(0, plugins_dir)
        for fn in os.listdir(plugins_dir):
            if not fn.endswith(".py"):
                continue
            mod_name = os.path.splitext(fn)[0]
            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, "Plugin"):
                    plugin_cls = getattr(mod, "Plugin")
                    plugin = plugin_cls()
                    self.register_plugin(plugin)
                    print(f"[PLUGIN] Loaded plugin: {plugin.name} ({plugin.type})")
            except Exception as e:
                print(f"[PLUGIN] Error loading plugin {fn}: {e}")

    def register_plugin(self, plugin: Any):
        self.plugins.append(plugin)
        for hook in getattr(plugin, "hooks", []):
            self.hooks.setdefault(hook, []).append(plugin)
        # sort by priority
        for hook, plist in self.hooks.items():
            plist.sort(key=lambda p: getattr(p, "priority", 100))

    def emit(self, event_name: str, **kwargs):
        for plugin in self.hooks.get(event_name, []):
            method_name = f"on_{event_name}"
            if hasattr(plugin, method_name):
                try:
                    getattr(plugin, method_name)(**kwargs)
                except Exception as e:
                    print(f"[PLUGIN] Error in {plugin.name}.{method_name}: {e}")

# =========================
# CORE ANALYZER (GPU-ACCELERATED WHEN AVAILABLE)
# =========================

class ImageAnalyzer:
    def __init__(self, libs: Dict[str, Any], tesseract_ok: bool = True, plugin_manager: Optional[PluginManager] = None):
        self.cv2 = libs["cv2"]
        self.np = libs["numpy"]
        self.PIL = libs["PIL"]
        self.pytesseract = libs["pytesseract"]
        self.tesseract_ok = tesseract_ok
        self.plugin_manager = plugin_manager

        # GPU detection
        self.use_cuda = False
        try:
            if hasattr(self.cv2, "cuda") and self.cv2.cuda.getCudaEnabledDeviceCount() > 0:
                self.use_cuda = True
                print("[GPU] OpenCV CUDA detected, GPU acceleration enabled.")
        except Exception:
            self.use_cuda = False

    def load_image(self, path: str):
        img = self.cv2.imread(path, self.cv2.IMREAD_COLOR)
        if img is None:
            raise FileNotFoundError(f"Cannot load image: {path}")
        if self.plugin_manager:
            self.plugin_manager.emit("image_loaded", path=path, img=img)
        return img

    def detect_layers_and_colors(self, img) -> List[Dict[str, Any]]:
        h, w, _ = img.shape
        bands = 4
        band_height = max(h // bands, 1)
        components: List[Dict[str, Any]] = []

        for i in range(bands):
            y1 = i * band_height
            y2 = (i + 1) * band_height if i < bands - 1 else h
            band = img[y1:y2, :]
            if band.size == 0:
                continue
            avg = band.mean(axis=(0, 1))
            components.append({
                "id": f"layer_{i+1}",
                "role_guess": ["CPU", "GPU", "MPU", "DPU"][i],
                "bbox": [0, int(y1), int(w), int(y2)],
                "avg_color_bgr": [float(avg[0]), float(avg[1]), float(avg[2])],
            })
        return components

    def detect_arrows(self, img) -> List[Dict[str, Any]]:
        cv2 = self.cv2
        np = self.np

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        if self.use_cuda:
            try:
                gpu_gray = cv2.cuda_GpuMat()
                gpu_gray.upload(gray)
                gpu_edges = cv2.cuda.createCannyEdgeDetector(100, 200).detect(gpu_gray)
                edges = gpu_edges.download()
            except Exception:
                edges = cv2.Canny(gray, 100, 200)
        else:
            edges = cv2.Canny(gray, 100, 200)

        lines = cv2.HoughLinesP(edges, 1, np.pi/180, threshold=80,
                                minLineLength=40, maxLineGap=10)
        arrows: List[Dict[str, Any]] = []
        if lines is not None:
            for idx, line in enumerate(lines[:100]):
                x1, y1, x2, y2 = line[0]
                arrows.append({
                    "id": f"arrow_{idx+1}",
                    "start": [int(x1), int(y1)],
                    "end": [int(x2), int(y2)],
                    "direction": "down" if y2 > y1 else "up",
                })
        return arrows

    def extract_text(self, img) -> str:
        if not self.tesseract_ok:
            return "(Tesseract not detected — see diagnostics in the app.)"
        try:
            rgb = self.cv2.cvtColor(img, self.cv2.COLOR_BGR2RGB)
            pil_img = self.PIL.Image.fromarray(rgb)
            return self.pytesseract.image_to_string(pil_img).strip()
        except Exception as e:
            return f"(OCR error: {e})"

    def build_local_blueprint(self, path: str) -> Dict[str, Any]:
        img = self.load_image(path)
        blueprint = {
            "source_image": os.path.basename(path),
            "mode": "local",
            "components": self.detect_layers_and_colors(img),
            "arrows": self.detect_arrows(img),
            "ocr_text": self.extract_text(img),
        }
        if self.plugin_manager:
            self.plugin_manager.emit("blueprint_built", path=path, img=img, blueprint=blueprint)
        return blueprint

# =========================
# AI MANAGER (LOCAL RUNTIMES + LM STUDIO AUTO-DETECT + MODEL FILES + INTERNET)
# =========================

LOCAL_RUNTIME_PORTS = {
    "Ollama": 11434,
    "LM Studio": 1234,
    "GPT4All": 5000,
    "KoboldCPP": 5001,
    "TextGenWebUI": 7860,
}

MODEL_EXTENSIONS = [
    ".gguf", ".ggml", ".onnx", ".bin", ".safetensors", ".pth"
]

class AIManager:
    def __init__(self, libs: Dict[str, Any], plugin_manager: Optional[PluginManager] = None):
        self.libs = libs
        self.requests = libs.get("requests")
        self.local_runtimes: List[Dict[str, Any]] = []
        self.local_models: List[Dict[str, Any]] = []
        self.internet_apis: List[Dict[str, Any]] = []
        self.active_source: Optional[Dict[str, Any]] = None
        self.plugin_manager = plugin_manager

        self._load_default_internet_apis()

    def _load_default_internet_apis(self):
        self.internet_apis = [
            {
                "name": "OpenAI (example)",
                "url": "https://api.openai.com/v1/chat/completions",
                "requires_key": True,
                "env_key": "OPENAI_API_KEY",
            },
        ]

    def _check_port(self, host: str, port: int, timeout: float = 0.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def scan_local_runtimes(self) -> List[Dict[str, Any]]:
        runtimes: List[Dict[str, Any]] = []
        for name, port in LOCAL_RUNTIME_PORTS.items():
            reachable = self._check_port("127.0.0.1", port)
            rt = {
                "name": name,
                "port": port,
                "reachable": reachable,
                "endpoint": f"http://127.0.0.1:{port}",
            }

            # LM Studio auto-detection
            if name == "LM Studio" and reachable and self.requests:
                try:
                    url = f"http://127.0.0.1:{port}/v1/models"
                    resp = self.requests.get(url, timeout=3)
                    if resp.status_code == 200:
                        data = resp.json()
                        rt["models"] = data.get("data", [])
                        if rt["models"]:
                            rt["active_model"] = rt["models"][0].get("id")
                except Exception as e:
                    rt["lmstudio_error"] = str(e)

            runtimes.append(rt)

        self.local_runtimes = runtimes
        if self.plugin_manager:
            self.plugin_manager.emit("ai_runtimes_scanned", runtimes=runtimes)
        return runtimes

    def scan_model_files(self, roots: List[str]) -> List[Dict[str, Any]]:
        models: List[Dict[str, Any]] = []
        for root in roots:
            root = os.path.expanduser(root)
            if not os.path.isdir(root):
                continue
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    for ext in MODEL_EXTENSIONS:
                        if fn.lower().endswith(ext):
                            full = os.path.join(dirpath, fn)
                            try:
                                size = os.path.getsize(full)
                            except OSError:
                                size = 0
                            models.append({
                                "name": fn,
                                "path": full,
                                "ext": ext,
                                "size_bytes": size,
                            })
                            break
        self.local_models = models
        if self.plugin_manager:
            self.plugin_manager.emit("model_files_scanned", models=models)
        return models

    def test_internet_apis(self) -> List[Dict[str, Any]]:
        if not self.requests:
            return []
        results: List[Dict[str, Any]] = []
        for api in self.internet_apis:
            url = api["url"]
            key_env = api.get("env_key")
            key_val = os.environ.get(key_env) if key_env else None
            headers = {}
            if key_val:
                headers["Authorization"] = f"Bearer {key_val}"
            try:
                resp = self.requests.get(url, headers=headers, timeout=3)
                ok = resp.status_code < 500
                results.append({
                    "name": api["name"],
                    "url": url,
                    "reachable": ok,
                    "status_code": resp.status_code,
                })
            except Exception as e:
                results.append({
                    "name": api["name"],
                    "url": url,
                    "reachable": False,
                    "error": str(e),
                })
        if self.plugin_manager:
            self.plugin_manager.emit("internet_apis_tested", results=results)
        return results

    def set_active_source(self, source: Dict[str, Any]):
        self.active_source = source
        if self.plugin_manager:
            self.plugin_manager.emit("active_ai_source_set", source=source)

    def choose_best_source(self) -> Optional[Dict[str, Any]]:
        for rt in self.local_runtimes:
            if rt["reachable"]:
                self.active_source = {"type": "local_runtime", **rt}
                if self.plugin_manager:
                    self.plugin_manager.emit("active_ai_source_set", source=self.active_source)
                return self.active_source

        if self.internet_apis and self.requests:
            tested = self.test_internet_apis()
            for res in tested:
                if res.get("reachable"):
                    self.active_source = {
                        "type": "internet_api",
                        "name": res["name"],
                        "url": res["url"],
                    }
                    if self.plugin_manager:
                        self.plugin_manager.emit("active_ai_source_set", source=self.active_source)
                    return self.active_source

        if self.local_models:
            self.active_source = {
                "type": "local_model",
                "model": self.local_models[0],
            }
            if self.plugin_manager:
                self.plugin_manager.emit("active_ai_source_set", source=self.active_source)
            return self.active_source

        self.active_source = None
        return None

# =========================
# AI INTERPRETER
# =========================

class AIInterpreter:
    def __init__(self, libs: Dict[str, Any], ai_manager: AIManager, plugin_manager: Optional[PluginManager] = None):
        self.libs = libs
        self.requests = libs.get("requests")
        self.ai_manager = ai_manager
        self.plugin_manager = plugin_manager

    def _resolve_url_and_payload(self, src: Dict[str, Any], blueprint: Dict[str, Any]) -> (str, Dict[str, Any]):
        bp_json = json.dumps(blueprint)

        # Ollama: /api/generate, JSON prompt
        if src["type"] == "local_runtime" and src.get("name") == "Ollama":
            port = src.get("port", 11434)
            url = f"http://127.0.0.1:{port}/api/generate"
            payload = {
                "model": "llama2",
                "prompt": f"Analyze this processor cube blueprint:\n{bp_json}",
            }
            return url, payload

        # LM Studio: OpenAI-compatible /v1/chat/completions
        if src["type"] == "local_runtime" and src.get("name") == "LM Studio":
            port = src.get("port", 1234)
            url = f"http://127.0.0.1:{port}/v1/chat/completions"
            model_id = src.get("active_model", "lmstudio")
            payload = {
                "model": model_id,
                "messages": [
                    {
                        "role": "user",
                        "content": f"Analyze this processor cube blueprint:\n{bp_json}",
                    }
                ],
            }
            return url, payload

        if src["type"] == "local_runtime":
            url = src.get("endpoint", "")
            payload = {"blueprint": blueprint}
            return url, payload

        if src["type"] == "internet_api":
            url = src.get("url", "")
            payload = {"blueprint": blueprint}
            return url, payload

        return "", {"blueprint": blueprint}

    def interpret_blueprint(self, blueprint: Dict[str, Any]) -> Dict[str, Any]:
        src = self.ai_manager.active_source or self.ai_manager.choose_best_source()
        if not src:
            return {
                "summary": "No AI source available — using local-only interpretation.",
                "components": blueprint.get("components", []),
            }

        if src["type"] in ("local_runtime", "internet_api"):
            if not self.requests:
                return {
                    "summary": "AI source detected but 'requests' missing.",
                    "components": blueprint.get("components", []),
                }
            try:
                url, payload = self._resolve_url_and_payload(src, blueprint)
                if self.plugin_manager:
                    self.plugin_manager.emit("ai_request", source=src, url=url, payload=payload, blueprint=blueprint)
                if not url:
                    return {
                        "summary": "AI URL could not be resolved.",
                        "components": blueprint.get("components", []),
                    }
                resp = self.requests.post(url, json=payload, timeout=60)
                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text}
                if self.plugin_manager:
                    self.plugin_manager.emit("ai_response", source=src, url=url, payload=payload, response=data)
                return data
            except Exception as e:
                return {
                    "summary": f"AI call failed: {e}",
                    "components": blueprint.get("components", []),
                }

        if src["type"] == "local_model":
            return {
                "summary": f"Local model detected ({src['model']['name']}) but direct inference not wired.",
                "components": blueprint.get("components", []),
            }

        return {
            "summary": "Unknown AI source type.",
            "components": blueprint.get("components", []),
        }

# =========================
# GUI APPLICATION
# =========================

class ProcessorCubeApp:
    def __init__(self, root, gui_libs: Dict[str, Any]):
        self.root = root
        self.tk = gui_libs["tkinter"]
        self.ttk = gui_libs["tkinter.ttk"]
        self.filedialog = gui_libs["tkinter.filedialog"]
        self.messagebox = gui_libs["tkinter.messagebox"]
        self.tkinterdnd2 = gui_libs.get("tkinterdnd2")

        self.dnd_available = self.tkinterdnd2 is not None
        self.libs: Dict[str, Any] = {}
        self.image_paths: List[str] = []
        self.mode = "local"

        self.preview_img = None
        self.preview_tk = None

        self.tesseract_ok = False
        self.tesseract_diag = ""

        self.plugin_manager = PluginManager()
        self.plugin_manager.load_plugins()

        self.ai_manager: Optional[AIManager] = None

        self.ollama_model_var = None

        self.watchdog_thread: Optional[threading.Thread] = None
        self.watchdog_running = False
        self.watchdog_folder: Optional[str] = None
        self.watchdog_seen: set = set()

        self._build_ui()

    def _build_ui(self):
        self.root.title("Processor Cube Ultra Command Center")

        main = self.ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")

        self.status = self.tk.StringVar(value="Status: Ready.")
        self.ttk.Label(main, textvariable=self.status).grid(row=0, column=0, columnspan=7, sticky="w")

        self.ttk.Button(main, text="Load Core Libraries", command=self.load_core).grid(row=1, column=0, sticky="ew")
        self.ttk.Button(main, text="Load AI Libraries", command=self.load_ai).grid(row=1, column=1, sticky="ew")

        self.ttk.Label(main, text="Mode:").grid(row=1, column=2, sticky="w")
        self.mode_var = self.tk.StringVar(value="local")
        mode_box = self.ttk.Combobox(main, textvariable=self.mode_var,
                                     values=["local", "hybrid", "ai_only"], state="readonly")
        mode_box.grid(row=1, column=3, sticky="ew")
        mode_box.bind("<<ComboboxSelected>>", lambda e: self.set_mode())

        self.ttk.Button(main, text="Tesseract Diagnostics", command=self.show_tesseract_diag).grid(row=1, column=4, sticky="ew")

        self.ttk.Button(main, text="Select PNG/JPG(s)", command=self.select_pngs).grid(row=2, column=0, sticky="ew")
        self.image_label = self.ttk.Label(main, text="No images selected.")
        self.image_label.grid(row=2, column=1, columnspan=6, sticky="w")

        dnd_text = "Drag PNG/JPG(s) here" if self.dnd_available else "Drag-and-drop unavailable"
        self.drop_zone = self.ttk.Label(main, text=dnd_text, relief="ridge", padding=20)
        self.drop_zone.grid(row=3, column=0, columnspan=7, sticky="nsew", pady=10)

        if self.dnd_available:
            DND_FILES = self.tkinterdnd2.DND_FILES
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self.on_drop)

        preview_frame = self.ttk.LabelFrame(main, text="Preview & Visualization")
        preview_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=10)

        self.preview_canvas = self.tk.Canvas(preview_frame, width=320, height=240, bg="black")
        self.preview_canvas.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=5, pady=5)

        self.layers_text = self.tk.Text(preview_frame, width=40, height=8)
        self.layers_text.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.layers_text.insert("1.0", "Layer visualization will appear here.")

        self.arrows_canvas = self.tk.Canvas(preview_frame, width=320, height=120, bg="gray20")
        self.arrows_canvas.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        self.ttk.Button(preview_frame, text="Clear Preview", command=self.clear_preview).grid(
            row=2, column=1, sticky="e", padx=5, pady=5
        )

        ai_frame = self.ttk.LabelFrame(main, text="AI Sources & Chat")
        ai_frame.grid(row=4, column=3, columnspan=4, sticky="nsew", pady=10)

        self.ttk.Button(ai_frame, text="Scan Local Runtimes", command=self.scan_local_runtimes).grid(row=0, column=0, columnspan=4, sticky="ew", padx=5, pady=2)
        self.ttk.Button(ai_frame, text="Scan Model Files", command=self.scan_model_files).grid(row=1, column=0, columnspan=4, sticky="ew", padx=5, pady=2)
        self.ttk.Button(ai_frame, text="Test Internet APIs", command=self.test_internet_apis).grid(row=2, column=0, columnspan=4, sticky="ew", padx=5, pady=2)

        self.ai_source_var = self.tk.StringVar(value="Auto-select")
        self.ttk.Label(ai_frame, text="Active AI Source:").grid(row=3, column=0, sticky="w", padx=5)
        self.ai_source_box = self.ttk.Combobox(ai_frame, textvariable=self.ai_source_var,
                                               values=["Auto-select", "Local Runtime", "Internet API", "Local Model"],
                                               state="readonly")
        self.ai_source_box.grid(row=3, column=1, columnspan=3, sticky="ew", padx=5)
        self.ai_source_box.bind("<<ComboboxSelected>>", lambda e: self.update_active_ai_source())

        self.ttk.Label(ai_frame, text="Ollama model:").grid(row=4, column=0, sticky="w", padx=5)
        self.ollama_model_var = self.tk.StringVar(value="llama2")
        self.ttk.Entry(ai_frame, textvariable=self.ollama_model_var).grid(row=4, column=1, columnspan=3, sticky="ew", padx=5)

        self.ai_info_text = self.tk.Text(ai_frame, width=40, height=8)
        self.ai_info_text.grid(row=5, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        self.ai_info_text.insert("1.0", "AI source info will appear here.")

        chat_frame = self.ttk.LabelFrame(ai_frame, text="Chat with Active AI")
        chat_frame.grid(row=6, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)

        self.chat_log = self.tk.Text(chat_frame, width=40, height=10, state="disabled")
        self.chat_log.grid(row=0, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)

        self.chat_input = self.tk.Entry(chat_frame)
        self.chat_input.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        self.ttk.Button(chat_frame, text="Send Text", command=self.send_text_message).grid(row=1, column=3, sticky="ew", padx=5, pady=5)
        self.ttk.Button(chat_frame, text="Send Image Blueprint", command=self.send_image_blueprint).grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        self.ttk.Button(chat_frame, text="Send Raw Image", command=self.send_raw_image_to_ai).grid(row=2, column=2, columnspan=2, sticky="ew", padx=5, pady=5)

        self.ttk.Button(main, text="Run & Save (Single)", command=self.run_single).grid(
            row=5, column=0, columnspan=2, sticky="ew", pady=10
        )
        self.ttk.Button(main, text="Run Batch & Save Folder", command=self.run_batch).grid(
            row=5, column=2, columnspan=2, sticky="ew", pady=10
        )
        self.ttk.Button(main, text="Compare Selected Images", command=self.compare_images).grid(
            row=5, column=4, columnspan=1, sticky="ew", pady=10
        )
        self.ttk.Button(main, text="Watch Folder (Auto-Process)", command=self.setup_watchdog).grid(
            row=5, column=5, columnspan=2, sticky="ew", pady=10
        )

        for c in range(7):
            main.columnconfigure(c, weight=1)
        main.rowconfigure(3, weight=1)
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.columnconfigure(1, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        preview_frame.rowconfigure(1, weight=1)
        ai_frame.columnconfigure(0, weight=1)
        ai_frame.columnconfigure(1, weight=1)
        ai_frame.columnconfigure(2, weight=1)
        ai_frame.columnconfigure(3, weight=1)
        ai_frame.rowconfigure(5, weight=1)
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.columnconfigure(1, weight=1)
        chat_frame.columnconfigure(2, weight=1)
        chat_frame.columnconfigure(3, weight=0)
        chat_frame.rowconfigure(0, weight=1)

    def set_status(self, msg: str):
        self.status.set(f"Status: {msg}")
        self.root.update_idletasks()

    # ---------- TESSERACT ----------

    def check_tesseract(self):
        try:
            pyt = self.libs.get("pytesseract")
            if pyt is None:
                self.tesseract_ok = False
                self.tesseract_diag = "pytesseract Python package is missing (should have been auto-installed)."
                return
            _ = pyt.get_tesseract_version()
            self.tesseract_ok = True
            self.tesseract_diag = "Tesseract detected and ready."
        except Exception as e:
            self.tesseract_ok = False
            self.tesseract_diag = (
                "Tesseract (external program) not found or not in PATH.\n\n"
                "To fix:\n"
                "  1) Download Tesseract for Windows from:\n"
                "     https://github.com/UB-Mannheim/tesseract/wiki\n"
                "  2) Install it (default location is fine).\n"
                "  3) Make sure the install folder (e.g. C:\\Program Files\\Tesseract-OCR)\n"
                "     is added to your system PATH, or set pytesseract.pytesseract.tesseract_cmd\n"
                "     to the full path of tesseract.exe.\n\n"
                f"Error detail: {e}"
            )

    def show_tesseract_diag(self):
        if not self.tesseract_diag:
            self.check_tesseract()
        if not self.tesseract_ok:
            self.messagebox.showwarning("Tesseract Diagnostics", self.tesseract_diag)
        else:
            self.messagebox.showinfo("Tesseract Diagnostics", self.tesseract_diag)

    # ---------- LIB LOADING ----------

    def load_core(self):
        def task():
            self.set_status("Loading core libs (auto-install if missing)...")
            self.libs.update(autoload(all_ai=False))
            self.check_tesseract()
            self.ai_manager = AIManager(self.libs, plugin_manager=self.plugin_manager)
            self.set_status("Core libraries loaded." + (" Tesseract OK." if self.tesseract_ok else " Tesseract NOT detected — see diagnostics."))
        threading.Thread(target=task, daemon=True).start()

    def load_ai(self):
        def task():
            self.set_status("Loading AI libs (auto-install if missing)...")
            self.libs.update(autoload(all_ai=True))
            if not self.ai_manager:
                self.ai_manager = AIManager(self.libs, plugin_manager=self.plugin_manager)
            self.set_status("AI libraries loaded.")
        threading.Thread(target=task, daemon=True).start()

    def set_mode(self):
        self.mode = self.mode_var.get()
        self.set_status(f"Mode set to {self.mode}")

    # ---------- IMAGE SELECTION / DND ----------

    def select_pngs(self):
        raw_paths = self.filedialog.askopenfilenames(
            title="Select PNG/JPG(s)",
            filetypes=[("Image files", "*.png *.jpg *.jpeg"), ("PNG files", "*.png"), ("JPEG files", "*.jpg *.jpeg")]
        )
        if not raw_paths:
            self.set_status("Image selection canceled.")
            return

        paths: List[str] = []
        for rp in raw_paths:
            p = normalize_single_path(rp)
            if os.path.isfile(p) and p.lower().endswith((".png", ".jpg", ".jpeg")):
                paths.append(p)

        if not paths:
            self.set_status("No valid image files selected.")
            return

        self.image_paths = paths
        self.image_label.config(text=f"{len(paths)} image(s) selected.")
        self.set_status("Images selected.")
        self.auto_preview_first()

    def on_drop(self, event):
        raw = event.data
        paths = normalize_dropped_data(raw)

        valid: List[str] = []
        for p in paths:
            if os.path.isfile(p) and p.lower().endswith((".png", ".jpg", ".jpeg")):
                valid.append(p)

        if not valid:
            self.set_status(f"Dropped item is not a valid image file. Raw: {raw}")
            return

        self.image_paths = valid
        self.image_label.config(text=f"{len(valid)} image(s) selected via drag-and-drop.")
        self.set_status("Images selected via drag-and-drop.")
        self.auto_preview_first()

    # ---------- PREVIEW ----------

    def auto_preview_first(self):
        if not self.image_paths:
            return
        if "cv2" not in self.libs or "PIL" not in self.libs:
            self.set_status("Core libs not loaded; preview unavailable.")
            return

        path = self.image_paths[0]
        try:
            analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)
            img = analyzer.load_image(path)

            cv2 = self.libs["cv2"]
            h, w, _ = img.shape
            scale = min(320 / w, 240 / h)
            new_w = max(int(w * scale), 1)
            new_h = max(int(h * scale), 1)
            resized = cv2.resize(img, (new_w, new_h))

            rgb = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB)
            pil_img = self.libs["PIL"].Image.fromarray(rgb)

            self.preview_img = pil_img
            self.preview_tk = self.tk.PhotoImage(data=self._pil_to_tk_bytes(pil_img))
            self.preview_canvas.delete("all")
            self.preview_canvas.create_image(160, 120, image=self.preview_tk)

            blueprint = analyzer.build_local_blueprint(path)
            self.update_layer_visualization(blueprint)
            self.update_arrows_minimap(blueprint)

            self.set_status(f"Preview updated for: {os.path.basename(path)}")
        except Exception as e:
            self.set_status(f"Preview error: {e}")

    def _pil_to_tk_bytes(self, pil_img):
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        return buf.getvalue()

    def clear_preview(self):
        self.preview_canvas.delete("all")
        self.arrows_canvas.delete("all")
        self.layers_text.delete("1.0", "end")
        self.layers_text.insert("1.0", "Layer visualization will appear here.")
        self.set_status("Preview cleared.")

    def update_layer_visualization(self, blueprint: Dict[str, Any]):
        self.layers_text.delete("1.0", "end")
        comps = blueprint.get("components", [])
        if not comps:
            self.layers_text.insert("1.0", "No components detected.")
            return

        lines = []
        for c in comps:
            lines.append(
                f"{c['id']} ({c['role_guess']}): "
                f"bbox={c['bbox']}, avg_bgr={c['avg_color_bgr']}"
            )
        self.layers_text.insert("1.0", "\n".join(lines))

    def update_arrows_minimap(self, blueprint: Dict[str, Any]):
        self.arrows_canvas.delete("all")
        arrows = blueprint.get("arrows", [])
        if not arrows:
            self.arrows_canvas.create_text(
                160, 60, text="No arrows detected.", fill="white"
            )
            return

        xs: List[int] = []
        ys: List[int] = []
        for a in arrows:
            xs.extend([a["start"][0], a["end"][0]])
            ys.extend([a["start"][1], a["end"][1]])

        min_x = min(xs) if xs else 0
        max_x = max(xs) if xs else 1
        min_y = min(ys) if ys else 0
        max_y = max(ys) if ys else 1

        width = 320
        height = 120

        def norm_x(x: int) -> float:
            return (x - min_x) / max(1, (max_x - min_x)) * width

        def norm_y(y: int) -> float:
            return (y - min_y) / max(1, (max_y - min_y)) * height

        for a in arrows:
            x1 = norm_x(a["start"][0])
            y1 = norm_y(a["start"][1])
            x2 = norm_x(a["end"][0])
            y2 = norm_y(a["end"][1])
            self.arrows_canvas.create_line(
                x1, y1, x2, y2, fill="cyan", width=2, arrow=self.tk.LAST
            )

    # ---------- AI SOURCE UI ----------

    def scan_local_runtimes(self):
        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load core/AI libraries first.")
            return

        def task():
            self.set_status("Scanning local AI runtimes...")
            runtimes = self.ai_manager.scan_local_runtimes()
            lines = ["Local AI Runtimes:"]
            for rt in runtimes:
                extra = ""
                if rt["name"] == "LM Studio" and rt.get("active_model"):
                    extra = f" (active model: {rt['active_model']})"
                lines.append(
                    f"- {rt['name']} on port {rt['port']} "
                    f"({'reachable' if rt['reachable'] else 'not reachable'}){extra}"
                )
            self.ai_info_text.delete("1.0", "end")
            self.ai_info_text.insert("1.0", "\n".join(lines))
            self.set_status("Local runtime scan complete.")
        threading.Thread(target=task, daemon=True).start()

    def scan_model_files(self):
        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load core/AI libraries first.")
            return

        roots = [
            os.path.expanduser("~"),
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Downloads"),
            r"C:\Users\tbarr\AppData\Local\Programs\Ollama\lib\ollama",
        ]

        def task():
            self.set_status("Scanning for local model files (common dirs + Ollama)...")
            models = self.ai_manager.scan_model_files(roots)
            lines = ["Local Model Files:"]
            if not models:
                lines.append("No model files found in scanned directories.")
            else:
                for m in models[:100]:
                    size_mb = m["size_bytes"] / (1024 * 1024) if m["size_bytes"] else 0
                    lines.append(
                        f"- {m['name']} ({m['ext']}) ~ {size_mb:.2f} MB\n  {m['path']}"
                    )
                if len(models) > 100:
                    lines.append(f"... and {len(models) - 100} more.")
            self.ai_info_text.delete("1.0", "end")
            self.ai_info_text.insert("1.0", "\n".join(lines))
            self.set_status("Model file scan complete.")
        threading.Thread(target=task, daemon=True).start()

    def test_internet_apis(self):
        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load AI libraries first.")
            return

        def task():
            self.set_status("Testing internet AI APIs...")
            results = self.ai_manager.test_internet_apis()
            lines = ["Internet AI APIs:"]
            if not results:
                lines.append("No 'requests' library or APIs configured.")
            else:
                for r in results:
                    if r.get("reachable"):
                        lines.append(
                            f"- {r['name']} ({r['url']}) reachable, status {r['status_code']}"
                        )
                    else:
                        lines.append(
                            f"- {r['name']} ({r['url']}) NOT reachable: {r.get('error', r.get('status_code'))}"
                        )
            self.ai_info_text.delete("1.0", "end")
            self.ai_info_text.insert("1.0", "\n".join(lines))
            self.set_status("Internet API test complete.")
        threading.Thread(target=task, daemon=True).start()

    def update_active_ai_source(self):
        if not self.ai_manager:
            return
        choice = self.ai_source_var.get()
        if choice == "Auto-select":
            src = self.ai_manager.choose_best_source()
            if src:
                self.set_status(f"AI source auto-selected: {src.get('name', src.get('type'))}")
            else:
                self.set_status("No AI source available.")
        elif choice == "Local Runtime":
            if self.ai_manager.local_runtimes:
                rt = next((r for r in self.ai_manager.local_runtimes if r["reachable"]), None)
                if not rt:
                    rt = self.ai_manager.local_runtimes[0]
                self.ai_manager.set_active_source({"type": "local_runtime", **rt})
                self.set_status(f"AI source set: Local Runtime ({rt['name']})")
            else:
                self.set_status("No local runtimes scanned yet.")
        elif choice == "Internet API":
            if self.ai_manager.internet_apis:
                api = self.ai_manager.internet_apis[0]
                self.ai_manager.set_active_source({
                    "type": "internet_api",
                    "name": api["name"],
                    "url": api["url"],
                })
                self.set_status(f"AI source set: Internet API ({api['name']})")
            else:
                self.set_status("No internet APIs configured.")
        elif choice == "Local Model":
            if self.ai_manager.local_models:
                self.ai_manager.set_active_source({
                    "type": "local_model",
                    "model": self.ai_manager.local_models[0],
                })
                self.set_status(f"AI source set: Local Model ({self.ai_manager.local_models[0]['name']})")
            else:
                self.set_status("No local models scanned yet.")

    # ---------- CHAT ----------

    def append_chat(self, prefix: str, text: str):
        self.chat_log.configure(state="normal")
        self.chat_log.insert("end", f"{prefix}: {text}\n")
        self.chat_log.see("end")
        self.chat_log.configure(state="disabled")

    def _get_active_chat_source(self) -> Optional[Dict[str, Any]]:
        if not self.ai_manager:
            return None
        src = self.ai_manager.active_source or self.ai_manager.choose_best_source()
        if not src:
            return None
        if src["type"] not in ("local_runtime", "internet_api"):
            return None
        return src

    def _resolve_chat_url(self, src: Dict[str, Any]) -> str:
        if src["type"] == "local_runtime" and src.get("name") == "Ollama":
            port = src.get("port", 11434)
            return f"http://127.0.0.1:{port}/api/generate"
        if src["type"] == "local_runtime" and src.get("name") == "LM Studio":
            port = src.get("port", 1234)
            return f"http://127.0.0.1:{port}/v1/chat/completions"
        if src["type"] == "local_runtime":
            return src.get("endpoint", "")
        if src["type"] == "internet_api":
            return src.get("url", "")
        return ""

    def send_text_message(self):
        msg = self.chat_input.get().strip()
        if not msg:
            return

        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load AI libraries and scan/select a source first.")
            return

        src = self._get_active_chat_source()
        if not src:
            self.messagebox.showwarning("AI Source", "Chat is only wired for local runtimes or internet APIs.")
            return

        if "requests" not in self.libs or self.libs["requests"] is None:
            self.messagebox.showwarning("Requests", "The 'requests' library is missing; load AI libraries first.")
            return

        self.append_chat("You", msg)
        self.chat_input.delete(0, "end")

        def task():
            try:
                self.set_status("Sending text message to active AI...")
                requests = self.libs["requests"]

                url = self._resolve_chat_url(src)
                if not url:
                    raise RuntimeError("AI URL could not be resolved.")

                if src["type"] == "local_runtime" and src.get("name") == "Ollama":
                    model_name = self.ollama_model_var.get().strip() if self.ollama_model_var else "llama2"
                    payload = {"model": model_name or "llama2", "prompt": msg}
                elif src["type"] == "local_runtime" and src.get("name") == "LM Studio":
                    model_id = src.get("active_model", "lmstudio")
                    payload = {
                        "model": model_id,
                        "messages": [{"role": "user", "content": msg}],
                    }
                else:
                    payload = {"prompt": msg}

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_request", source=src, url=url, payload=payload, blueprint=None)

                resp = requests.post(url, json=payload, timeout=60)
                resp.raise_for_status()
                try:
                    data = resp.json()
                    text = (
                        data.get("response")
                        or data.get("text")
                        or data.get("choices", [{}])[0].get("message", {}).get("content")
                        or str(data)
                    )
                except Exception:
                    text = resp.text

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_response", source=src, url=url, payload=payload, response=data)

                self.append_chat(src.get("name", "AI"), text)
                self.set_status("Chat response received.")
            except Exception as e:
                self.append_chat("System", f"Error sending text: {e}")
                self.set_status(f"Chat error: {e}")

        threading.Thread(target=task, daemon=True).start()

    def send_image_blueprint(self):
        if not self.image_paths:
            self.messagebox.showwarning("No Image", "Select or drop at least one image first.")
            return

        if "cv2" not in self.libs:
            self.messagebox.showwarning("Missing Core", "Load core libraries first.")
            return

        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load AI libraries and scan/select a source first.")
            return

        src = self._get_active_chat_source()
        if not src:
            self.messagebox.showwarning("AI Source", "Image send is only wired for local runtimes or internet APIs.")
            return

        if "requests" not in self.libs or self.libs["requests"] is None:
            self.messagebox.showwarning("Requests", "The 'requests' library is missing; load AI libraries first.")
            return

        path = self.image_paths[0]
        self.append_chat("System", f"Sending blueprint for image: {os.path.basename(path)}")

        def task():
            try:
                self.set_status("Building blueprint and sending to active AI...")
                analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)
                base_blueprint = analyzer.build_local_blueprint(path)

                requests = self.libs["requests"]
                url = self._resolve_chat_url(src)
                if not url:
                    raise RuntimeError("AI URL could not be resolved.")

                bp_json = json.dumps(base_blueprint)
                if src["type"] == "local_runtime" and src.get("name") == "Ollama":
                    model_name = self.ollama_model_var.get().strip() if self.ollama_model_var else "llama2"
                    payload = {
                        "model": model_name or "llama2",
                        "prompt": f"Analyze this processor cube blueprint:\n{bp_json}",
                    }
                elif src["type"] == "local_runtime" and src.get("name") == "LM Studio":
                    model_id = src.get("active_model", "lmstudio")
                    payload = {
                        "model": model_id,
                        "messages": [
                            {
                                "role": "user",
                                "content": f"Analyze this processor cube blueprint:\n{bp_json}",
                            }
                        ],
                    }
                else:
                    payload = {"blueprint": base_blueprint}

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_request", source=src, url=url, payload=payload, blueprint=base_blueprint)

                resp = requests.post(url, json=payload, timeout=120)
                resp.raise_for_status()
                try:
                    data = resp.json()
                    text = (
                        data.get("response")
                        or data.get("summary")
                        or data.get("text")
                        or data.get("choices", [{}])[0].get("message", {}).get("content")
                        or str(data)
                    )
                except Exception:
                    text = resp.text

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_response", source=src, url=url, payload=payload, response=data)

                self.append_chat(src.get("name", "AI"), text)
                self.set_status("Image blueprint response received.")
            except Exception as e:
                self.append_chat("System", f"Error sending image blueprint: {e}")
                self.set_status(f"Image send error: {e}")

        threading.Thread(target=task, daemon=True).start()

    def send_raw_image_to_ai(self):
        if not self.image_paths:
            self.messagebox.showwarning("No Image", "Select or drop at least one image first.")
            return

        if not self.ai_manager:
            self.messagebox.showwarning("AI Manager", "Load AI libraries and scan/select a source first.")
            return

        src = self._get_active_chat_source()
        if not src:
            self.messagebox.showwarning("AI Source", "Raw image send is only wired for local runtimes or internet APIs.")
            return

        if "requests" not in self.libs or self.libs["requests"] is None:
            self.messagebox.showwarning("Requests", "The 'requests' library is missing; load AI libraries first.")
            return

        path = self.image_paths[0]
        self.append_chat("System", f"Sending raw image to AI: {os.path.basename(path)}")

        def task():
            try:
                self.set_status("Encoding image and sending to active AI...")
                with open(path, "rb") as f:
                    img_bytes = f.read()
                img_b64 = base64.b64encode(img_bytes).decode("ascii")

                requests = self.libs["requests"]
                url = self._resolve_chat_url(src)
                if not url:
                    raise RuntimeError("AI URL could not be resolved.")

                if src["type"] == "local_runtime" and src.get("name") == "Ollama":
                    model_name = self.ollama_model_var.get().strip() if self.ollama_model_var else "llava"
                    payload = {
                        "model": model_name or "llava",
                        "prompt": "Describe this image and infer processor cube structure.",
                        "images": [img_b64],
                    }
                elif src["type"] == "local_runtime" and src.get("name") == "LM Studio":
                    # LM Studio may not support images; treat as text-only
                    payload = {
                        "model": src.get("active_model", "lmstudio"),
                        "messages": [
                            {
                                "role": "user",
                                "content": "Image bytes (base64) provided, but LM Studio may not support vision. Here is the base64:\n" + img_b64,
                            }
                        ],
                    }
                else:
                    payload = {"image_base64": img_b64}

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_request", source=src, url=url, payload=payload, blueprint=None)

                resp = requests.post(url, json=payload, timeout=120)
                resp.raise_for_status()
                try:
                    data = resp.json()
                    text = (
                        data.get("response")
                        or data.get("summary")
                        or data.get("text")
                        or data.get("choices", [{}])[0].get("message", {}).get("content")
                        or str(data)
                    )
                except Exception:
                    text = resp.text

                if self.plugin_manager:
                    self.plugin_manager.emit("ai_response", source=src, url=url, payload=payload, response=data)

                self.append_chat(src.get("name", "AI"), text)
                self.set_status("Raw image response received.")
            except Exception as e:
                self.append_chat("System", f"Error sending raw image: {e}")
                self.set_status(f"Raw image send error: {e}")

        threading.Thread(target=task, daemon=True).start()

    # ---------- RUN / SAVE ----------

    def run_single(self):
        if not self.image_paths:
            self.messagebox.showwarning("No Image", "Select or drop at least one PNG/JPG first.")
            return

        if "cv2" not in self.libs:
            self.messagebox.showwarning("Missing Core", "Load core libraries first.")
            return

        path = self.image_paths[0]

        def task():
            try:
                self.set_status(f"Analyzing single: {os.path.basename(path)}")
                analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)

                base_blueprint = analyzer.build_local_blueprint(path)

                if self.mode == "local":
                    blueprint = base_blueprint
                else:
                    if not self.ai_manager:
                        self.ai_manager = AIManager(self.libs, plugin_manager=self.plugin_manager)
                    interpreter = AIInterpreter(self.libs, self.ai_manager, plugin_manager=self.plugin_manager)
                    ai_result = interpreter.interpret_blueprint(base_blueprint)
                    blueprint = {
                        "mode": self.mode,
                        "local_blueprint": base_blueprint,
                        "ai_interpretation": ai_result,
                    }

                save_path = self.filedialog.asksaveasfilename(
                    title="Save Blueprint (Single)",
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json")]
                )
                if not save_path:
                    self.set_status("Save canceled.")
                    return

                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(blueprint, f, indent=2)

                if self.plugin_manager:
                    self.plugin_manager.emit("blueprint_saved", path=save_path, blueprint=blueprint)

                self.set_status(f"Saved: {save_path}")
                self.messagebox.showinfo("Saved", f"Blueprint saved to:\n{save_path}")
            except Exception as e:
                self.set_status(f"Error: {e}")
                self.messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    def run_batch(self):
        if not self.image_paths:
            self.messagebox.showwarning("No Images", "Select or drop PNG/JPGs first.")
            return

        if "cv2" not in self.libs:
            self.messagebox.showwarning("Missing Core", "Load core libraries first.")
            return

        folder = self.filedialog.askdirectory(
            title="Select Folder to Save Batch Blueprints"
        )
        if not folder:
            self.set_status("Batch save folder selection canceled.")
            return

        def task():
            try:
                analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)
                if not self.ai_manager:
                    self.ai_manager = AIManager(self.libs, plugin_manager=self.plugin_manager)
                interpreter = AIInterpreter(self.libs, self.ai_manager, plugin_manager=self.plugin_manager)
                count = 0

                for path in self.image_paths:
                    self.set_status(f"Batch analyzing: {os.path.basename(path)}")
                    base_blueprint = analyzer.build_local_blueprint(path)

                    if self.mode == "local":
                        blueprint = base_blueprint
                    else:
                        ai_result = interpreter.interpret_blueprint(base_blueprint)
                        blueprint = {
                            "mode": self.mode,
                            "local_blueprint": base_blueprint,
                            "ai_interpretation": ai_result,
                        }

                    base_name = os.path.splitext(os.path.basename(path))[0]
                    out_path = os.path.join(folder, f"{base_name}_blueprint.json")
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(blueprint, f, indent=2)

                    if self.plugin_manager:
                        self.plugin_manager.emit("blueprint_saved", path=out_path, blueprint=blueprint)

                    count += 1

                self.set_status(f"Batch complete: {count} blueprint(s) saved.")
                self.messagebox.showinfo(
                    "Batch Complete",
                    f"Saved {count} blueprint(s) to:\n{folder}"
                )
            except Exception as e:
                self.set_status(f"Batch error: {e}")
                self.messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ---------- MULTI-IMAGE COMPARISON ----------

    def compare_images(self):
        if len(self.image_paths) < 2:
            self.messagebox.showwarning("Not Enough Images", "Select at least two images to compare.")
            return

        if "cv2" not in self.libs:
            self.messagebox.showwarning("Missing Core", "Load core libraries first.")
            return

        def task():
            try:
                self.set_status("Comparing selected images...")
                analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)
                blueprints = []
                for path in self.image_paths:
                    bp = analyzer.build_local_blueprint(path)
                    blueprints.append((path, bp))

                # Simple comparison: show counts and differences
                lines = ["Multi-image comparison:"]
                for path, bp in blueprints:
                    comps = bp.get("components", [])
                    arrows = bp.get("arrows", [])
                    lines.append(
                        f"- {os.path.basename(path)}: {len(comps)} components, {len(arrows)} arrows"
                    )

                self.layers_text.delete("1.0", "end")
                self.layers_text.insert("1.0", "\n".join(lines))

                if self.plugin_manager:
                    self.plugin_manager.emit("comparison_done", blueprints=blueprints)

                self.set_status("Comparison complete.")
            except Exception as e:
                self.set_status(f"Comparison error: {e}")
                self.messagebox.showerror("Error", str(e))

        threading.Thread(target=task, daemon=True).start()

    # ---------- AUTO-WATCHDOG MODE ----------

    def setup_watchdog(self):
        folder = self.filedialog.askdirectory(
            title="Select Folder to Watch for New Images"
        )
        if not folder:
            self.set_status("Watchdog folder selection canceled.")
            return

        self.watchdog_folder = folder
        self.watchdog_seen = set(os.listdir(folder))
        if not self.watchdog_running:
            self.watchdog_running = True
            self.watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
            self.watchdog_thread.start()
            self.set_status(f"Watchdog started on folder: {folder}")
            self.messagebox.showinfo("Watchdog", f"Watching folder:\n{folder}\nNew PNG/JPG files will be auto-processed.")
        else:
            self.set_status(f"Watchdog already running on folder: {self.watchdog_folder}")

    def _watchdog_loop(self):
        while self.watchdog_running and self.watchdog_folder:
            try:
                current = set(os.listdir(self.watchdog_folder))
                new_files = current - self.watchdog_seen
                self.watchdog_seen = current

                for fn in new_files:
                    full = os.path.join(self.watchdog_folder, fn)
                    if os.path.isfile(full) and full.lower().endswith((".png", ".jpg", ".jpeg")):
                        self.set_status(f"Watchdog detected new image: {fn}")
                        if self.plugin_manager:
                            self.plugin_manager.emit("watchdog_new_file", path=full)

                        # Auto-process and save blueprint next to file
                        try:
                            analyzer = ImageAnalyzer(self.libs, tesseract_ok=self.tesseract_ok, plugin_manager=self.plugin_manager)
                            base_blueprint = analyzer.build_local_blueprint(full)

                            if not self.ai_manager:
                                self.ai_manager = AIManager(self.libs, plugin_manager=self.plugin_manager)
                            interpreter = AIInterpreter(self.libs, self.ai_manager, plugin_manager=self.plugin_manager)

                            if self.mode == "local":
                                blueprint = base_blueprint
                            else:
                                ai_result = interpreter.interpret_blueprint(base_blueprint)
                                blueprint = {
                                    "mode": self.mode,
                                    "local_blueprint": base_blueprint,
                                    "ai_interpretation": ai_result,
                                }

                            base_name = os.path.splitext(os.path.basename(full))[0]
                            out_path = os.path.join(self.watchdog_folder, f"{base_name}_blueprint.json")
                            with open(out_path, "w", encoding="utf-8") as f:
                                json.dump(blueprint, f, indent=2)

                            if self.plugin_manager:
                                self.plugin_manager.emit("blueprint_saved", path=out_path, blueprint=blueprint)

                            self.set_status(f"Watchdog saved blueprint: {out_path}")
                        except Exception as e:
                            self.set_status(f"Watchdog error on {fn}: {e}")
                time.sleep(2.0)
            except Exception as e:
                self.set_status(f"Watchdog loop error: {e}")
                time.sleep(5.0)

    # =========================
    # MAIN
    # =========================

def main():
    bootloader_check()
    gui_libs = load_gui_modules()

    if gui_libs.get("tkinterdnd2"):
        root = gui_libs["tkinterdnd2"].TkinterDnD.Tk()
    else:
        root = gui_libs["tkinter"].Tk()

    app = ProcessorCubeApp(root, gui_libs)
    root.mainloop()

if __name__ == "__main__":
    main()
