# === AUTO-ELEVATION CHECK (Windows only) ===
import os, sys, platform, ctypes

def ensure_admin():
    try:
        if platform.system() == "Windows":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                script = os.path.abspath(sys.argv[0])
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{script}" {params}', None, 1
                )
                sys.exit()
    except Exception as e:
        print(f"[Beast] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# === BEAST GLOBAL HYBRID FULL ===

import time
import json
import socket
import threading
import logging
import http.server
import socketserver
import subprocess
import numpy as np

# Optional extras
try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

try:
    import tkinter as tk
    from tkinter import ttk
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

# --- Force all files into script folder ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "beast.log")
CFG_PATH = os.path.join(BASE_DIR, "beast_config.json")

# ========================= LOGGING =========================

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def beast_log(msg: str):
    print(f"[BEAST] {msg}", flush=True)
    logging.info(msg)


# ========================= SAFE GPU DETECTION =========================

def safe_gpu_available():
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["rocminfo"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    return False


# ========================= CONFIG / PROFILES =========================

DEFAULT_CONFIG = {
    "profile": "balanced",
    "daemon_mode": False,
    "distributed": {
        "enabled": False,
        "port": 50555,
        "broadcast_interval": 2.0
    },
    "gui": {"enabled": True},
    "remote": {
        "enabled": True,
        "port": 8080
    },
    "organism_targets": {},
    "enable_gpu": False,
}

PROFILES = {
    "balanced": {
        "organisms": [
            {"name": "AlphaCPU", "type": "cpu", "target_util": 0.3},
            {"name": "BetaCPU", "type": "cpu", "target_util": 0.3},
            {"name": "GammaGPU", "type": "gpu", "target_util": 0.3},
        ]
    },
    "full": {
        "organisms": [
            {"name": "AlphaCPU", "type": "cpu", "target_util": 0.8},
            {"name": "BetaCPU", "type": "cpu", "target_util": 0.8},
            {"name": "GammaGPU", "type": "gpu", "target_util": 0.8},
        ]
    },
    "silent": {
        "organisms": [
            {"name": "AlphaCPU", "type": "cpu", "target_util": 0.05},
        ]
    },
}


def load_config(path=CFG_PATH):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            if "organism_targets" not in cfg:
                cfg["organism_targets"] = {}
            if "enable_gpu" not in cfg:
                cfg["enable_gpu"] = False
            return cfg
        except Exception:
            pass
    cfg = DEFAULT_CONFIG.copy()
    cfg["organism_targets"] = {}
    return cfg


def save_config(cfg, path=CFG_PATH):
    try:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


# ========================= CORE WORKLOADS =========================

def cpu_vector_cycle(size: int = 300_000) -> float:
    x = np.random.rand(size).astype("float64")
    y = np.random.rand(size).astype("float64")
    s = np.sin(x)
    c = np.cos(y)
    out = s * c
    return float(out.sum())


def gpu_vector_cycle(size: int = 300_000, gpu_enabled: bool = False) -> float:
    if not gpu_enabled:
        return cpu_vector_cycle(size)

    if not safe_gpu_available():
        return cpu_vector_cycle(size)

    try:
        import cupy as cp
        x = cp.random.rand(size, dtype=cp.float64)
        y = cp.random.rand(size, dtype=cp.float64)
        s = cp.sin(x)
        c = cp.cos(y)
        out = s * c
        return float(out.sum().get())
    except Exception:
        return cpu_vector_cycle(size)


# ========================= ORGANISMS =========================

class Organism:
    def __init__(self, name: str, kind: str, target_util: float):
        self.name = name
        self.kind = kind  # "cpu" or "gpu"
        self.target_util = max(0.0, min(target_util, 1.0))  # 0–1 from slider
        self.last_util = 0.0
        self.last_temp = None

    def set_from_slider(self, v: float):
        self.target_util = max(0.0, min(v, 1.0))


# ========================= GLOBAL ENGINE (HYBRID GOVERNOR) =========================

class BeastEngine:
    def __init__(self, organisms, cfg):
        self.organisms = organisms
        self.cfg = cfg
        self.gpu_enabled = bool(cfg.get("enable_gpu", False))
        self.cycle = 0
        self.last_cpu_util = 0.0
        self.last_temp = None
        self.running = True

        # Hybrid governor parameters
        self.min_iters = 1
        self.max_iters = 80  # crank this up if you want more bite
        self.base_vec_size = 300_000

        self.lock = threading.Lock()

        if PSUTIL:
            psutil.cpu_percent(interval=None)

    def _measure_cpu(self):
        if not PSUTIL:
            return None, None
        util = psutil.cpu_percent(interval=None)
        temp = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for _, entries in temps.items():
                    if entries:
                        temp = entries[0].current
                        break
        except Exception:
            pass
        return util, temp

    def _compute_global_load(self) -> float:
        # Global load L in [0,1] = average of organism sliders
        if not self.organisms:
            return 0.0
        s = sum(o.target_util for o in self.organisms)
        return s / len(self.organisms)

    def _hybrid_iterations(self, L: float) -> int:
        # Hybrid absolute + additive on CPU:
        # factor = L in [0,1]
        # iterations = min_iters + factor * (max_iters - min_iters)
        factor = max(0.0, min(L, 1.0))
        iters = int(self.min_iters + factor * (self.max_iters - self.min_iters))
        return max(self.min_iters, iters)

    def worker_loop(self):
        while self.running:
            self.cycle += 1

            # 1) Compute global load from sliders
            L = self._compute_global_load()
            iters = self._hybrid_iterations(L)

            # 2) Burn CPU/GPU according to global iterations
            for _ in range(iters):
                for o in self.organisms:
                    if o.kind == "cpu":
                        cpu_vector_cycle(self.base_vec_size)
                    elif o.kind == "gpu":
                        gpu_vector_cycle(self.base_vec_size, self.gpu_enabled)

            # 3) Telemetry (display only, not used for control)
            util, temp = self._measure_cpu()
            with self.lock:
                if util is not None:
                    self.last_cpu_util = util
                self.last_temp = temp

            beast_log(
                f"Cycle {self.cycle} | L={L:.2f} | iters={iters} | "
                f"CPU={self.last_cpu_util:.1f}% | Temp={self.last_temp if self.last_temp is not None else 'N/A'}C"
            )

            # Small sleep to avoid total lockup
            time.sleep(0.2)


# ========================= DISTRIBUTED HEARTBEAT =========================

class BeastNetwork:
    def __init__(self, cfg):
        self.enabled = cfg.get("distributed", {}).get("enabled", False)
        self.port = cfg.get("distributed", {}).get("port", 50555)
        self.interval = cfg.get("distributed", {}).get("broadcast_interval", 2.0)
        self.stop_flag = threading.Event()
        self.thread = None

    def start(self):
        if not self.enabled:
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_flag.set()

    def _run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        hostname = socket.gethostname()
        while not self.stop_flag.is_set():
            msg = f"BEAST_HEARTBEAT {hostname}"
            try:
                sock.sendto(msg.encode("utf-8"), ("255.255.255.255", self.port))
            except Exception:
                pass
            time.sleep(self.interval)


# ========================= REMOTE API (READ/WRITE ENGINE) =========================

class RemoteHandler(http.server.BaseHTTPRequestHandler):
    engine_ref = None
    cfg_ref = None

    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/status":
            e = self.engine_ref
            if e is None:
                self._send_json({"error": "no engine"}, 500)
                return
            with e.lock:
                util = e.last_cpu_util
                temp = e.last_temp
                cycle = e.cycle
            data = {
                "cycle": cycle,
                "util": util,
                "temp": temp,
                "gpu_enabled": e.gpu_enabled,
                "organisms": [
                    {
                        "name": o.name,
                        "kind": o.kind,
                        "target_util": o.target_util,
                    }
                    for o in e.organisms
                ],
            }
            self._send_json(data)
        else:
            self._send_json({"error": "unknown endpoint"}, 404)

    def do_POST(self):
        if self.path.startswith("/set_target"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self._send_json({"error": "invalid json"}, 400)
                return
            name = payload.get("name")
            target = payload.get("target_util")
            e = self.engine_ref
            cfg = self.cfg_ref
            if e is None or cfg is None:
                self._send_json({"error": "no engine"}, 500)
                return
            found = False
            try:
                tval = float(target)
            except Exception:
                self._send_json({"error": "invalid target"}, 400)
                return
            tval = max(0.0, min(tval, 1.0))
            for o in e.organisms:
                if o.name == name:
                    o.set_from_slider(tval)
                    cfg["organism_targets"][name] = tval
                    save_config(cfg)
                    found = True
                    break
            if not found:
                self._send_json({"error": "organism not found"}, 404)
            else:
                self._send_json({"status": "ok"})
        elif self.path.startswith("/set_gpu_enabled"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self._send_json({"error": "invalid json"}, 400)
                return
            enabled = bool(payload.get("enabled", False))
            e = self.engine_ref
            cfg = self.cfg_ref
            if e is None or cfg is None:
                self._send_json({"error": "no engine"}, 500)
                return
            e.gpu_enabled = enabled
            cfg["enable_gpu"] = enabled
            save_config(cfg)
            self._send_json({"status": "ok", "gpu_enabled": enabled})
        else:
            self._send_json({"error": "unknown endpoint"}, 404)


class RemoteServer:
    def __init__(self, cfg, engine: BeastEngine):
        self.enabled = cfg.get("remote", {}).get("enabled", True)
        self.port = cfg.get("remote", {}).get("port", 8080)
        self.engine = engine
        self.cfg = cfg
        self.thread = None

    def start(self):
        if not self.enabled:
            return
        RemoteHandler.engine_ref = self.engine
        RemoteHandler.cfg_ref = self.cfg

        def run_server():
            with socketserver.TCPServer(("", self.port), RemoteHandler) as httpd:
                beast_log(f"Remote control listening on port {self.port}")
                httpd.serve_forever()

        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()


# ========================= GUI COCKPIT =========================

class BeastGUI:
    def __init__(self, engine: BeastEngine, cfg):
        self.engine = engine
        self.cfg = cfg
        self.root = tk.Tk()
        self.root.title("Beast Global CPU+GPU Cockpit (Hybrid Governor)")
        self.info_label = None
        self.sliders = {}
        self.gpu_var = tk.BooleanVar(value=self.engine.gpu_enabled)
        self.update_interval_ms = 1000
        self._build_ui()

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

        self.info_label = ttk.Label(frame, text="Initializing…", anchor="w", justify="left")
        self.info_label.pack(fill="x", pady=(0, 10))

        org_frame = ttk.LabelFrame(frame, text="Organism Weights (0–100%)")
        org_frame.pack(fill="x")

        for o in self.engine.organisms:
            row = ttk.Frame(org_frame)
            row.pack(fill="x", pady=2)

            name_label = ttk.Label(row, text=f"{o.name} ({o.kind})", width=18)
            name_label.pack(side="left")

            val_label = ttk.Label(row, text=f"{int(o.target_util * 100)}%", width=5)
            val_label.pack(side="right")

            slider = ttk.Scale(
                row,
                from_=0,
                to=100,
                orient="horizontal",
                command=lambda val, org=o, lab=val_label: self._on_slider(org, val, lab),
            )
            slider.set(o.target_util * 100)
            slider.pack(side="right", fill="x", expand=True, padx=5)

            self.sliders[o.name] = slider

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(10, 0))

        save_btn = ttk.Button(btn_frame, text="Save Settings", command=self._save_settings)
        save_btn.pack(side="left", padx=5)

        reset_btn = ttk.Button(btn_frame, text="Reset Weights", command=self._reset_targets)
        reset_btn.pack(side="left", padx=5)

        gpu_check = ttk.Checkbutton(
            frame,
            text="Enable GPU work (if available)",
            variable=self.gpu_var,
            command=self._toggle_gpu
        )
        gpu_check.pack(fill="x", pady=(10, 0))

    def _on_slider(self, org: Organism, val, label_widget):
        try:
            v = float(val)
        except:
            return
        label_widget.config(text=f"{int(v)}%")
        mapped = max(0.0, min(v / 100.0, 1.0))
        org.set_from_slider(mapped)
        self.cfg["organism_targets"][org.name] = mapped
        save_config(self.cfg)

    def _save_settings(self):
        for o in self.engine.organisms:
            self.cfg["organism_targets"][o.name] = o.target_util
        self.cfg["enable_gpu"] = self.engine.gpu_enabled
        save_config(self.cfg)
        beast_log("Settings saved from GUI")

    def _reset_targets(self):
        for o in self.engine.organisms:
            o.set_from_slider(0.0)
            slider = self.sliders.get(o.name)
            if slider is not None:
                slider.set(0)
        self.cfg["organism_targets"] = {}
        save_config(self.cfg)
        beast_log("Weights reset to 0 (silent)")

    def _toggle_gpu(self):
        enabled = bool(self.gpu_var.get())
        self.engine.gpu_enabled = enabled
        self.cfg["enable_gpu"] = enabled
        save_config(self.cfg)
        beast_log(f"GPU enabled set to {enabled}")

    def update(self):
        with self.engine.lock:
            util = self.engine.last_cpu_util
            temp = self.engine.last_temp
            cycle = self.engine.cycle

        L = self.engine._compute_global_load()
        iters = self.engine._hybrid_iterations(L)

        lines = [
            f"Cycle: {cycle}",
            f"Global Load L: {L:.2f}",
            f"Hybrid iters: {iters}",
            f"CPU Util: {util:.1f}%" if util is not None else "CPU Util: N/A",
            f"Temp: {temp if temp is not None else 'N/A'}C",
            f"GPU Enabled: {self.engine.gpu_enabled}",
        ]
        for o in self.engine.organisms:
            lines.append(f"{o.name} [{o.kind}] weight={int(o.target_util*100)}%")

        self.info_label.config(text="\n".join(lines))
        self.root.after(self.update_interval_ms, self.update)

    def run(self):
        self.update()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self.engine.running = False
        self.root.destroy()


# ========================= DAEMON MODE =========================

def daemonize_if_requested(cfg):
    if not cfg.get("daemon_mode", False):
        return
    if platform.system().lower() == "windows":
        return
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(os.devnull, "a+") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())


# ========================= MAIN =========================

def main():
    cfg = load_config()
    profile_name = cfg.get("profile", "balanced")
    profile = PROFILES.get(profile_name, PROFILES["balanced"])

    daemonize_if_requested(cfg)

    beast_log(f"Starting BEAST GLOBAL HYBRID FULL | profile={profile_name}")
    beast_log(
        f"Platform: {platform.system()} | psutil={PSUTIL} | "
        f"tkinter={TK_AVAILABLE} | gpu_enabled={cfg.get('enable_gpu', False)}"
    )

    organisms = []
    for o in profile["organisms"]:
        base_target = o["target_util"]
        override = cfg["organism_targets"].get(o["name"])
        target = override if override is not None else base_target
        organisms.append(Organism(o["name"], o["type"], target))

    engine = BeastEngine(organisms, cfg)

    # Start worker
    worker = threading.Thread(target=engine.worker_loop, daemon=True)
    worker.start()

    # Start heartbeat
    net = BeastNetwork(cfg)
    net.start()

    # Start remote API
    remote = RemoteServer(cfg, engine)
    remote.start()

    gui_enabled = cfg.get("gui", {}).get("enabled", True) and TK_AVAILABLE

    if gui_enabled:
        gui = BeastGUI(engine, cfg)
        gui.run()
    else:
        try:
            while engine.running:
                time.sleep(1.0)
        except KeyboardInterrupt:
            engine.running = False


if __name__ == "__main__":
    main()

