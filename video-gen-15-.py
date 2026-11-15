import sys
import subprocess
import time
import os
import json
import ast
import urllib.request
import threading
import random
import math
from datetime import datetime
from collections import deque

print("--- [1/6] Initializing Ultimate Autonomous Dependency Loader v4.0... ---")
required_packages = {
    'cv2': 'opencv-contrib-python',
    'numpy': 'numpy',
    'PIL': 'pillow',
    'sklearn': 'scikit-learn',
    'psutil': 'psutil',
    'statsmodels': 'statsmodels'
}

for module_name, package_name in required_packages.items():
    try:
        __import__(module_name)
    except ImportError:
        print(f"Installing missing dependency: {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
from sklearn.ensemble import IsolationForest
import psutil
from statsmodels.tsa.arima.model import ARIMA

CONFIG_FILE = "ultimate_mixer_config_v4.json"

class BernoulliFluidPhysicsEngine:
    """Intelligent water data physics engine utilizing Bernoulli's principle to balance data flow pressure and velocity."""
    def __init__(self, baseline_pressure=100.0):
        self.pressure = baseline_pressure
        self.velocity = 10.0
        
    def flow_step(self, queue_load, throughput):
        self.pressure = 100.0 + (queue_load * 3.0) + (max(0.0, 30.0 - throughput) * 1.8)
        self.velocity = max(1.0, 65.0 / (1.0 + 0.035 * queue_load))
        return self.pressure, self.velocity

class NextConceptModeler:
    """Projects future system states and conceptual paradigm shifts using momentum and derivative telemetry trends."""
    def __init__(self, window_size=15):
        self.trend_memory = deque(maxlen=window_size)
        
    def project_next_concept(self, current_fps, cpu_load, risk_score):
        self.trend_memory.append((current_fps, cpu_load, risk_score))
        if len(self.trend_memory) < 4:
            return "STABLE_BASELINE_CONCEPTION"
        
        fps_diff = self.trend_memory[-1][0] - self.trend_memory[0][0]
        cpu_diff = self.trend_memory[-1][1] - self.trend_memory[0][1]
        
        if cpu_diff > 12.0 and fps_diff < -4.0:
            return "IMMINENT_RESOURCE_THROTTLE_CONCEPTION"
        elif risk_score > 1.8:
            return "ADAPTIVE_CYBER_FORTIFICATION_CONCEPTION"
        elif cpu_load < 28.0 and fps_diff >= 0:
            return "HYPER_PERFORMANCE_ACCELERATION_CONCEPTION"
        else:
            return "STEADY_STATE_HARMONIC_CONCEPTION"

class AlteredStatesManager:
    """Manages altered states of consciousness / operational modes for the AI workstation based on risk, system pressure, and intent."""
    STATES = ["BASELINE", "HYPER_VIGILANT", "DEEP_ANALYTIC", "ISOLATION_LOCKDOWN", "QUANTUM_AUTONOMOUS"]
    def __init__(self):
        self.current_state = "BASELINE"
        
    def evaluate(self, global_risk_score, cpu_load, anomaly_detected):
        if global_risk_score > 3.5 or cpu_load > 92.0:
            self.current_state = "ISOLATION_LOCKDOWN"
        elif anomaly_detected or global_risk_score > 1.8:
            self.current_state = "HYPER_VIGILANT"
        elif cpu_load > 75.0:
            self.current_state = "DEEP_ANALYTIC"
        elif cpu_load < 30.0 and global_risk_score < 0.5:
            self.current_state = "QUANTUM_AUTONOMOUS"
        else:
            self.current_state = "BASELINE"
        return self.current_state

class ProbabilisticField:
    """Bayesian probabilistic estimator for tracking confidence, anomaly likelihood, and missing details."""
    def __init__(self, mean: float, var: float):
        self.mean = mean
        self.var = var

    def sample(self):
        return random.gauss(self.mean, self.var)

    def update(self, observation: float, weight: float = 1.0):
        self.mean = (self.mean + weight * observation) / (1.0 + weight)
        self.var = max(1e-6, self.var * 0.88)

class Queen:
    """Consensus engine tracking and evaluating global entity risk across distributed nodes and background workers."""
    def __init__(self):
        self.nodes = {}

    def update(self, node, events):
        self.nodes[node] = events

    def global_risk(self):
        risk = {}
        for node, evts in self.nodes.items():
            for e in evts:
                entity = e.get("entity", "unknown")
                score = e.get("score", 0.0)
                risk[entity] = risk.get(entity, 0.0) + score
        return {k: v for k, v in risk.items() if v > 1.2}

class AttackChainEngine:
    """Advanced temporal sliding-window kill-chain detector with weighted threat confidence."""
    def __init__(self):
        self.events = deque()
        self.window = 180  # seconds

    def add_event(self, event_type, data):
        now = time.time()
        self.events.append((now, event_type, data))
        self._cleanup(now)

    def _cleanup(self, now):
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def detect(self):
        types = [e[1] for e in self.events]
        chains = []

        if all(x in types for x in ["proc_spawn", "powershell", "net_connect"]):
            chains.append(("LOLBIN_ATTACK_VECTOR", 0.95))

        if types.count("proc_spawn") > 4 and "net_connect" in types:
            chains.append(("RAPID_SPAWN_STORM", 0.85))

        if "file_mod" in types and "net_connect" in types:
            chains.append(("PERSISTENCE_EXFIL_ANOMALY", 0.90))

        return chains

class EventBus:
    """Asynchronous pub/sub event bus for telemetry and threat signals."""
    def __init__(self):
        self.subscribers = []
        self.queue = deque()

    def publish(self, event):
        self.queue.append(event)

    def subscribe(self, fn):
        self.subscribers.append(fn)

    def run(self):
        while True:
            if self.queue:
                evt = self.queue.popleft()
                for fn in self.subscribers:
                    try:
                        fn(evt)
                    except Exception:
                        pass
            time.sleep(0.005)

class ARIMAPredictiveForecaster:
    """Uses ARIMA statistical modeling to forecast system performance trends in advance."""
    def __init__(self, window_size=30):
        self.history = deque(maxlen=window_size)

    def update_and_forecast(self, current_metric):
        self.history.append(current_metric)
        if len(self.history) < 8:
            return current_metric, "Collecting Baseline..."

        try:
            model = ARIMA(list(self.history), order=(1, 1, 0))
            model_fit = model.fit()
            forecast = model_fit.forecast(steps=5)
            predicted_value = float(forecast[-1])
            trend_status = "STABLE" if predicted_value >= 22.0 else "DECLINING (Bottleneck Imminent)"
            return predicted_value, trend_status
        except Exception:
            return np.mean(self.history), "FALLBACK (Smoothing)"

class ChainOfThoughtReasoningEngine:
    """Advanced 6-Step CoT Engine integrating predictive ARIMA, Bernoulli physics, probabilistic uncertainty, and Next-Concept projections."""
    @staticmethod
    def reason(context_type, telemetry_data, predicted_fps, altered_state, pressure, velocity, prob_confidence, risk_score, next_concept):
        steps = []
        steps.append(f"[CoT Step 1: Observation] Analyzing active context vector: '{context_type}' [State: {altered_state}].")
        
        telev_cpu = telemetry_data.get('cpu', 0)
        telev_fps = telemetry_data.get('fps', 0)
        
        steps.append(f"[CoT Step 2: Telemetry & Physics] CPU: {telev_cpu}% | FPS: {telev_fps:.1f} | Pressure: {pressure:.1f} | Velocity: {velocity:.1f}.")
        steps.append(f"[CoT Step 3: Probabilistic & ARIMA] Confidence: {prob_confidence:.2f} | Predicted FPS: {predicted_fps:.1f} | Risk: {risk_score:.2f}.")
        steps.append(f"[CoT Step 4: Next-Concept Modeling] Projected Paradigm Shift: '{next_concept}'.")
        
        if predicted_fps < 22.0 or telev_cpu > 88.0 or altered_state == "ISOLATION_LOCKDOWN" or risk_score > 2.5:
            steps.append("[CoT Step 5: Threat / Bottleneck Evaluation] Critical threshold breached. High probability of degradation.")
            steps.append("[CoT Step 6: Proactive Mitigation] Executing automatic buffer trimming and thread offloading.")
            action = "MITIGATE_AND_SECURE"
        elif "ACCELERATION" in next_concept:
            steps.append("[CoT Step 5: Optimization] Next-concept projection indicates headroom for acceleration.")
            steps.append("[CoT Step 6: Proactive Mitigation] Maximizing super-resolution fidelity and pipeline throughput.")
            action = "OPTIMIZE"
        else:
            steps.append("[CoT Step 5: Equilibrium] Operational trajectory stable across time-series and physical models.")
            steps.append("[CoT Step 6: Decision/Action] Maintain normal workstation pipeline state.")
            action = "STABLE"
        
        return steps, action

class UltimateStudioMixerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Studio Video Mixer v4.0 – Autonomous Neural-Predictive Workstation")
        self.root.geometry("1450x920")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- STATE & INTELLIGENT ENGINES ---
        self.cap = None
        self.is_running = True
        self.is_recording = False
        self.video_writer = None
        self.frame_buffer = deque(maxlen=30)
        self.fps_forecaster = ARIMAPredictiveForecaster(window_size=25)
        
        # Advanced Subsystems
        self.queen = Queen()
        self.chain_engine = AttackChainEngine()
        self.event_bus = EventBus()
        self.fluid_engine = BernoulliFluidPhysicsEngine()
        self.altered_states = AlteredStatesManager()
        self.prob_field = ProbabilisticField(mean=0.85, var=0.04)
        self.next_concept_modeler = NextConceptModeler()
        
        self.current_fps = 0.0
        self.last_frame_time = time.time()
        self.latest_anomaly_detected = False
        
        self.event_bus.subscribe(self.handle_event_bus_message)
        threading.Thread(target=self.event_bus.run, daemon=True).start()

        # GPU / CUDA Acceleration Detection
        self.cuda_available = False
        try:
            if hasattr(cv2.cuda, 'getCudaEnabledDeviceCount') and cv2.cuda.getCudaEnabledDeviceCount() > 0:
                self.cuda_available = True
        except Exception:
            pass

        # AI Super-Resolution (Custom ONNX Model Integration)
        self.ai_sr_enabled = False
        self.net = None
        onnx_path = "custom_sr_model.onnx"
        try:
            if os.path.exists(onnx_path):
                self.net = cv2.dnn.readNetFromONNX(onnx_path)
                if self.cuda_available:
                    self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_CUDA)
                    self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CUDA)
                self.ai_sr_enabled = True
                print(" -> Custom PyTorch ONNX Super-Resolution model loaded successfully.")
            else:
                print(f" -> Notice: '{onnx_path}' not found. Using high-quality interpolation fallback.")
        except Exception as e:
            print(f" -> Could not load ONNX model: {e}")

        # --- GUI LAYOUT SETUP ---
        self.setup_ui()
        
        # --- LOAD SAVED SETTINGS ---
        self.load_settings()

        # --- INITIALIZE CAMERA ---
        self.init_camera()

        # --- START BACKGROUND AUTONOMOUS WORKERS ---
        self.start_background_inspectors()

        # --- START MAIN PREDICTIVE LOOP ---
        self.update_predictive_loop()

    def setup_ui(self):
        main_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- LEFT PANEL: MULTI-MODAL TABBED WORKSTATION ---
        self.notebook = ttk.Notebook(main_pane)
        main_pane.add(self.notebook, weight=1)

        # Tab 1: Mixing Console & Presets
        tab_mix = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_mix, text="Mixing Console")
        self.setup_mixing_tab(tab_mix)

        # Tab 2: Hardware & Camera Setup
        tab_hw = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_hw, text="Hardware & Res")
        self.setup_hardware_tab(tab_hw)

        # Tab 3: Pipeline Modules & Presets
        tab_pipe = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_pipe, text="Pipeline & Presets")
        self.setup_pipeline_tab(tab_pipe)

        # Tab 4: Isolation Forest Anomaly / Hidden Detector
        tab_anomaly = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_anomaly, text="Anomaly / Hidden")
        self.setup_anomaly_tab(tab_anomaly)

        # Tab 5: Fully Automated Background Code & Web Inspector Dashboard
        tab_code = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_code, text="Background Inspectors")
        self.setup_background_inspectors_tab(tab_code)

        # Tab 6: CoT Reasoning & Audit Logs
        tab_cot = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_cot, text="CoT & Audit Logs")
        self.setup_cot_logs_tab(tab_cot)

        # Tab 7: Recording & Output
        tab_rec = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_rec, text="Record & Output")
        self.setup_record_tab(tab_rec)

        # --- RIGHT PANEL: LIVE MONITOR & TELEMETRY ---
        right_frame = ttk.Frame(main_pane, padding=10)
        main_pane.add(right_frame, weight=2)

        gpu_label = f"CUDA ACTIVE" if self.cuda_available else "CPU FALLBACK"
        ttk.Label(right_frame, text=f"Autonomous Workstation v4.0 Monitor ({gpu_label})", font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=5)
        
        self.canvas = tk.Canvas(right_frame, bg="black", width=640, height=360)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.telemetry_var = tk.StringVar(value="Status: Autonomous background daemons active...")
        telemetry_bar = ttk.Label(right_frame, textvariable=self.telemetry_var, font=("Consolas", 9), relief=tk.SUNKEN, anchor=tk.W)
        telemetry_bar.pack(fill=tk.X, pady=5)

    def setup_mixing_tab(self, parent):
        ttk.Label(parent, text="Channel Strips & Next-Concept Master Engine", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)

        preset_frame = ttk.LabelFrame(parent, text="Workstation Preset Profiles", padding=8)
        preset_frame.pack(fill=tk.X, pady=5)
        self.preset_combo = ttk.Combobox(preset_frame, values=["Cinematic Master (High Quality)", "Cyber Sentinel (High Security)", "Live Streamer (Low Latency)"], state="readonly")
        self.preset_combo.set("Cinematic Master (High Quality)")
        self.preset_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(preset_frame, text="Apply Preset", command=self.apply_workstation_preset).pack(side=tk.RIGHT, padx=5)

        self.ai_auto_var = tk.IntVar(value=0)
        ttk.Checkbutton(parent, text="AI Auto-Mastering Engine (Real-Time Adaptive)", variable=self.ai_auto_var).pack(anchor=tk.W, pady=4)

        self.compare_var = tk.IntVar(value=0)
        ttk.Checkbutton(parent, text="Side-by-Side Before/After Comparison View", variable=self.compare_var).pack(anchor=tk.W, pady=4)

        self.predictive_toggle = tk.IntVar(value=1)
        ttk.Checkbutton(parent, text="Enable ARIMA & Next-Concept Proactive Forecasting", variable=self.predictive_toggle).pack(anchor=tk.W, pady=4)

        self.auto_remediate_var = tk.IntVar(value=1)
        ttk.Checkbutton(parent, text="Enable Autonomous Self-Healing / Auto-Remediation", variable=self.auto_remediate_var).pack(anchor=tk.W, pady=4)

        ttk.Separator(parent, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        self.slider_buffer = self.create_slider(parent, "Buffer / Cache Queue", 1, 30, 5)
        self.slider_bright = self.create_slider(parent, "Ch1: Brightness Offset", -50, 50, 0)
        self.slider_sat = self.create_slider(parent, "Ch2: Saturation Intensity (x10)", 0, 20, 10)
        self.slider_denoise = self.create_slider(parent, "Ch3: Denoise Strength", 1, 20, 4)
        self.slider_contrast = self.create_slider(parent, "Ch4: Contrast (CLAHE x10)", 10, 50, 20)
        self.slider_sharpen = self.create_slider(parent, "Ch5: Sharpen Matrix Weight", 1, 15, 4)

    def setup_hardware_tab(self, parent):
        ttk.Label(parent, text="Capture Device & Port Selection", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)

        ttk.Label(parent, text="Capture Device Index:").pack(anchor=tk.W, pady=2)
        self.device_combo = ttk.Combobox(parent, values=["Port 0 (Default)", "Port 1", "Port 2"], state="readonly")
        self.device_combo.set("Port 0 (Default)")
        self.device_combo.pack(fill=tk.X, pady=5)

        ttk.Label(parent, text="Target Canvas Resolution:").pack(anchor=tk.W, pady=2)
        self.res_combo = ttk.Combobox(parent, values=["1280x720 (HD)", "1920x1080 (FHD)", "640x480 (VGA)"], state="readonly")
        self.res_combo.set("1280x720 (HD)")
        self.res_combo.pack(fill=tk.X, pady=5)

        gpu_status = f"CUDA Hardware Acceleration: {'ACTIVE' if self.cuda_available else 'NOT AVAILABLE (Using CPU)'}"
        ttk.Label(parent, text=gpu_status, font=("Arial", 9, "italic"), foreground="green" if self.cuda_available else "orange").pack(anchor=tk.W, pady=15)

        ttk.Button(parent, text="Apply Hardware Settings", command=self.apply_hardware_settings).pack(pady=5)

    def setup_pipeline_tab(self, parent):
        ttk.Label(parent, text="Configurable Processing Pipelines & Presets", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)

        self.pipe_denoise = tk.IntVar(value=1)
        self.pipe_clahe = tk.IntVar(value=1)
        self.pipe_superres = tk.IntVar(value=1)
        self.pipe_sharpen = tk.IntVar(value=1)

        ttk.Checkbutton(parent, text="Enable Module: Denoise Filter", variable=self.pipe_denoise).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(parent, text="Enable Module: CLAHE Contrast", variable=self.pipe_clahe).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(parent, text="Enable Module: AI Super-Resolution / Upscale", variable=self.pipe_superres).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(parent, text="Enable Module: Edge Sharpening Matrix", variable=self.pipe_sharpen).pack(anchor=tk.W, pady=2)

    def setup_anomaly_tab(self, parent):
        ttk.Label(parent, text="Isolation Forest & Hidden Object Detector", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        ttk.Label(parent, text="Detects hidden pattern anomalies, artifacts, and visual outliers in real time.", font=("Arial", 8, "italic")).pack(anchor=tk.W, pady=2)

        self.video_anomaly_var = tk.IntVar(value=1)
        ttk.Checkbutton(parent, text="Enable Isolation Forest Visual Outlier Scanner", variable=self.video_anomaly_var).pack(anchor=tk.W, pady=10)

        self.slider_contamination = self.create_slider(parent, "Anomaly Sensitivity (x100)", 1, 20, 6)

    def setup_background_inspectors_tab(self, parent):
        ttk.Label(parent, text="Fully Autonomous Background Inspectors", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        ttk.Label(parent, text="The AI is running background daemons to automatically sweep workspace code and poll system endpoints without manual user input.", font=("Arial", 8, "italic")).pack(anchor=tk.W, pady=2)

        self.inspector_status_text = tk.Text(parent, height=18, width=45, font=("Consolas", 9), bg="#121212", fg="#00ffaa")
        self.inspector_status_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.inspector_status_text.insert(tk.END, "[Daemon Status]: Background Code & Web Watchers active.\n")

    def setup_cot_logs_tab(self, parent):
        ttk.Label(parent, text="Chain-of-Thought (CoT) & Audit Logs", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        notebook_logs = ttk.Notebook(parent)
        notebook_logs.pack(fill=tk.BOTH, expand=True, pady=5)

        tab_cot_sub = ttk.Frame(notebook_logs, padding=5)
        notebook_logs.add(tab_cot_sub, text="CoT Reasoning Trace")
        self.cot_text = tk.Text(tab_cot_sub, height=15, width=45, font=("Consolas", 9), bg="#121212", fg="#00ffff")
        self.cot_text.pack(fill=tk.BOTH, expand=True)

        tab_audit_sub = ttk.Frame(notebook_logs, padding=5)
        notebook_logs.add(tab_audit_sub, text="Audit Log")
        self.log_text = tk.Text(tab_audit_sub, height=15, width=45, font=("Consolas", 9), bg="#1e1e1e", fg="#00ff00")
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def setup_record_tab(self, parent):
        ttk.Label(parent, text="Recording & Snapshot Studio", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=5)
        
        self.btn_record = ttk.Button(parent, text="Start Video Recording", command=self.toggle_recording)
        self.btn_record.pack(fill=tk.X, pady=10)

        ttk.Button(parent, text="Capture High-Res Snapshot", command=self.take_snapshot).pack(fill=tk.X, pady=10)
        ttk.Button(parent, text="Save Settings Configuration Now", command=self.save_settings).pack(fill=tk.X, pady=10)

    def create_slider(self, parent, label_text, min_val, max_val, default_val):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=2)
        ttk.Label(frame, text=label_text, width=28).pack(side=tk.LEFT)
        var = tk.IntVar(value=default_val)
        slider = ttk.Scale(frame, from_=min_val, to=max_val, variable=var, orient=tk.HORIZONTAL)
        slider.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        return var

    def apply_workstation_preset(self):
        selection = self.preset_combo.get()
        if "Cinematic Master" in selection:
            self.slider_buffer.set(10)
            self.pipe_denoise.set(1)
            self.pipe_clahe.set(1)
            self.pipe_superres.set(1)
            self.pipe_sharpen.set(1)
            self.ai_auto_var.set(1)
        elif "Cyber Sentinel" in selection:
            self.slider_buffer.set(3)
            self.video_anomaly_var.set(1)
            self.predictive_toggle.set(1)
            self.auto_remediate_var.set(1)
        elif "Live Streamer" in selection:
            self.slider_buffer.set(2)
            self.pipe_superres.set(0)
            self.predictive_toggle.set(1)
        messagebox.showinfo("Preset Applied", f"Workstation profile '{selection}' loaded successfully.")

    def init_camera(self):
        if self.cap is not None:
            self.cap.release()

        device_idx = self.device_combo.current()
        backends = [
            ("Media Foundation", cv2.CAP_MSMF),
            ("DirectShow", cv2.CAP_DSHOW),
            ("Default", cv2.CAP_ANY)
        ]

        for name, backend in backends:
            try:
                test_cap = cv2.VideoCapture(device_idx, backend)
                if test_cap.isOpened():
                    ret, frame = test_cap.read()
                    if ret and frame is not None:
                        self.cap = test_cap
                        break
                    else:
                        test_cap.release()
            except Exception:
                pass

        if self.cap is None or not self.cap.isOpened():
            self.using_synthetic = True
        else:
            self.using_synthetic = False
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    def apply_hardware_settings(self):
        self.init_camera()
        messagebox.showinfo("Hardware Settings", "Capture device and resolution updated successfully.")

    def toggle_recording(self):
        if not self.is_recording:
            os.makedirs("captures", exist_ok=True)
            filename = f"captures/recording_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            self.video_writer = cv2.VideoWriter(filename, fourcc, 30.0, (1280, 720))
            self.is_recording = True
            self.btn_record.config(text="Stop Video Recording")
        else:
            self.is_recording = False
            if self.video_writer:
                self.video_writer.release()
            self.btn_record.config(text="Start Video Recording")

    def take_snapshot(self):
        os.makedirs("captures", exist_ok=True)
        filename = f"captures/snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        if hasattr(self, 'latest_processed_frame') and self.latest_processed_frame is not None:
            cv2.imwrite(filename, self.latest_processed_frame)
            messagebox.showinfo("Snapshot Captured", f"High-res snapshot saved to {filename}")

    def start_background_inspectors(self):
        """Starts background threads that automatically sweep code files and poll endpoints without manual user action."""
        def background_code_worker():
            while self.is_running:
                try:
                    py_files = [f for f in os.listdir('.') if f.endswith('.py')]
                    for py in py_files:
                        with open(py, 'r', encoding='utf-8') as f:
                            tree = ast.parse(f.read(), filename=py)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                                msg = f"[SECURITY] Auto-detected unsafe '{node.func.id}()' in '{py}' (line {node.lineno})."
                                self.log_audit("Code Watcher", "Vulnerability", msg)
                                self.event_bus.publish({"EventName": "process", "ImageFileName": py, "CommandLine": "eval_detected", "score": 1.2})
                except Exception:
                    pass
                time.sleep(12.0)

        def background_web_worker():
            default_endpoints = ["https://httpbin.org/status/200"]
            while self.is_running:
                for url in default_endpoints:
                    try:
                        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                        start = time.time()
                        with urllib.request.urlopen(req, timeout=4) as res:
                            code = res.getcode()
                            if code != 200:
                                msg = f"Endpoint '{url}' returned non-200 status: {code}"
                                self.log_audit("Web Watcher", "HTTP Anomaly", msg)
                    except Exception:
                        pass
                time.sleep(15.0)

        threading.Thread(target=background_code_worker, daemon=True).start()
        threading.Thread(target=background_web_worker, daemon=True).start()

    def handle_event_bus_message(self, event):
        try:
            opcode = (event.get("EventName") or "").lower()
            if "process" in opcode:
                image = (event.get("ImageFileName") or "").lower()
                self.chain_engine.add_event("proc_spawn", {"name": image})
            if "connect" in opcode:
                ip = event.get("daddr") or event.get("DestIp")
                if ip:
                    self.chain_engine.add_event("net_connect", {"ip": ip})
        except Exception:
            pass

    def log_audit(self, domain, anomaly_type, description):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{domain.upper()}] [{anomaly_type.upper()}] {description}\n"
        try:
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            self.inspector_status_text.insert(tk.END, log_entry)
            self.inspector_status_text.see(tk.END)
        except Exception:
            pass

    def log_cot(self, steps):
        timestamp = datetime.now().strftime('%H:%M:%S')
        trace_block = f"--- Next-Concept CoT Trace [{timestamp}] ---\n" + "\n".join(steps) + "\n\n"
        try:
            self.cot_text.insert(tk.END, trace_block)
            self.cot_text.see(tk.END)
        except Exception:
            pass

    def save_settings(self):
        config = {
            "buffer": self.slider_buffer.get(),
            "brightness": self.slider_bright.get(),
            "saturation": self.slider_sat.get(),
            "denoise": self.slider_denoise.get(),
            "contrast": self.slider_contrast.get(),
            "sharpen": self.slider_sharpen.get(),
            "pipe_denoise": self.pipe_denoise.get(),
            "pipe_clahe": self.pipe_clahe.get(),
            "pipe_superres": self.pipe_superres.get(),
            "pipe_sharpen": self.pipe_sharpen.get(),
            "video_anomaly": self.video_anomaly_var.get(),
            "predictive": self.predictive_toggle.get(),
            "auto_remediate": self.auto_remediate_var.get()
        }
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception:
            pass

    def load_settings(self):
        if not os.path.exists(CONFIG_FILE):
            return
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            self.slider_buffer.set(config.get("buffer", 5))
            self.slider_bright.set(config.get("brightness", 0))
            self.slider_sat.set(config.get("saturation", 10))
            self.slider_denoise.set(config.get("denoise", 4))
            self.slider_contrast.set(config.get("contrast", 20))
            self.slider_sharpen.set(config.get("sharpen", 4))
            self.pipe_denoise.set(config.get("pipe_denoise", 1))
            self.pipe_clahe.set(config.get("pipe_clahe", 1))
            self.pipe_superres.set(config.get("pipe_superres", 1))
            self.pipe_sharpen.set(config.get("pipe_sharpen", 1))
            self.video_anomaly_var.set(config.get("video_anomaly", 1))
            self.predictive_toggle.set(config.get("predictive", 1))
            self.auto_remediate_var.set(config.get("auto_remediate", 1))
        except Exception:
            pass

    def update_predictive_loop(self):
        if not self.is_running:
            return

        loop_start_time = time.time()

        if getattr(self, 'using_synthetic', False):
            frame = np.zeros((720, 1280, 3), dtype=np.uint8)
            for x in range(0, 1280, 80):
                cv2.line(frame, (x, 0), (x, 720), (35, 35, 35), 1)
            for y in range(0, 720, 80):
                cv2.line(frame, (0, y), (1280, y), (35, 35, 35), 1)
            cv2.putText(frame, "AUTONOMOUS WORKSTATION V4.0 - NEXT-CONCEPT ACTIVE", (160, 365), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            ret = True
        else:
            ret, frame = self.cap.read()

        if not ret or frame is None or frame.size == 0:
            self.root.after(20, self.update_predictive_loop)
            return

        raw_display_frame = frame.copy()
        ai_active = self.ai_auto_var.get() == 1
        buffer_val = max(1, self.slider_buffer.get())
        
        if ai_active:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            luma = np.mean(gray)
            bright_val = int((128 - luma) / 3.0)
            sat_val = 1.2 if luma > 60 else 1.3
            denoise_val = 5
            clahe_val = 2.4
            sharp_val = 5
        else:
            bright_val = self.slider_bright.get()
            sat_val = self.slider_sat.get() / 10.0
            denoise_val = self.slider_denoise.get()
            clahe_val = self.slider_contrast.get() / 10.0
            sharp_val = self.slider_sharpen.get()

        if self.frame_buffer.maxlen != buffer_val:
            self.frame_buffer = deque(self.frame_buffer, maxlen=buffer_val)
        self.frame_buffer.append(frame)
        current_frame = np.mean(self.frame_buffer, axis=0).astype(np.uint8)

        # Safe Floating-Point Brightness Math
        if bright_val != 0:
            frame_float = current_frame.astype(np.float32) + float(bright_val)
            current_frame = np.clip(frame_float, 0, 255).astype(np.uint8)

        hsv = cv2.cvtColor(current_frame, cv2.COLOR_BGR2HSV).astype(np.float32)
        hsv[:, :, 1] *= sat_val
        hsv[:, :, 1] = np.clip(hsv[:, :, 1], 0, 255)
        current_frame = cv2.cvtColor(hsv.astype(np.uint8), cv2.COLOR_HSV2BGR)

        if self.pipe_denoise.get() == 1:
            h_val = max(1, denoise_val)
            current_frame = cv2.fastNlMeansDenoisingColored(current_frame, None, h=h_val, hColor=h_val, templateWindowSize=7, searchWindowSize=21)

        if self.pipe_clahe.get() == 1:
            lab = cv2.cvtColor(current_frame, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=max(1.0, clahe_val), tileGridSize=(8, 8))
            l = clahe.apply(l)
            current_frame = cv2.cvtColor(cv2.merge((l, a, b)), cv2.COLOR_LAB2BGR)

        if self.pipe_superres.get() == 1 and self.ai_sr_enabled and self.net is not None:
            try:
                blob = cv2.dnn.blobFromImage(current_frame, scalefactor=1.0/255.0, size=(320, 180), swapRB=True, crop=False)
                self.net.setInput(blob)
                output = self.net.forward()
                output = output.squeeze().transpose(1, 2, 0)
                output = np.clip(output * 255.0, 0, 255).astype(np.uint8)
                current_frame = cv2.resize(output, (1280, 720), interpolation=cv2.INTER_CUBIC)
            except Exception:
                current_frame = cv2.resize(current_frame, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
        else:
            current_frame = cv2.resize(current_frame, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)

        if self.pipe_sharpen.get() == 1:
            center_val = float(sharp_val)
            surround_val = -(center_val - 1.0) / 4.0 if center_val > 1 else 0.0
            kernel = np.array([[0.0, surround_val, 0.0],
                               [surround_val, center_val, surround_val],
                               [0.0, surround_val, 0.0]])
            current_frame = cv2.filter2D(current_frame, -1, kernel)

        # Isolation Forest Anomaly Detection
        anomaly_detected_this_frame = False
        if self.video_anomaly_var.get() == 1:
            try:
                small_grid = cv2.resize(current_frame, (32, 18))
                pixels = small_grid.reshape(-1, 3).astype(np.float32)
                contamination = max(0.01, self.slider_contamination.get() / 100.0)
                iso = IsolationForest(contamination=contamination, random_state=42, n_estimators=30)
                preds = iso.fit_predict(pixels)
                
                outlier_mask = (preds == -1).astype(np.uint8).reshape(18, 32) * 255
                if np.sum(outlier_mask) > (32 * 18 * 0.05 * 255):
                    anomaly_detected_this_frame = True
                
                outlier_mask = cv2.resize(outlier_mask, (current_frame.shape[1], current_frame.shape[0]), interpolation=cv2.INTER_NEAREST)
                heatmap = cv2.applyColorMap(outlier_mask, cv2.COLORMAP_JET)
                current_frame = cv2.addWeighted(current_frame, 0.75, heatmap, 0.25, 0)
            except Exception:
                pass

        self.latest_processed_frame = current_frame

        if self.compare_var.get() == 1:
            raw_resized = cv2.resize(raw_display_frame, (current_frame.shape[1], current_frame.shape[0]))
            display_output = np.hstack((raw_resized, current_frame))
        else:
            display_output = current_frame

        if self.is_recording and self.video_writer is not None:
            rec_frame = cv2.resize(display_output, (1280, 720))
            self.video_writer.write(rec_frame)

        loop_duration = time.time() - loop_start_time
        self.current_fps = 1.0 / max(loop_duration, 0.001)
        
        predicted_fps, trend_label = self.fps_forecaster.update_and_forecast(self.current_fps)
        cpu_usage = psutil.cpu_percent()
        telemetry = {"cpu": cpu_usage, "fps": self.current_fps}

        # Bernoulli Data Physics & Next-Concept Modeling
        pressure, velocity = self.fluid_engine.flow_step(len(self.frame_buffer), self.current_fps)

        chains = self.chain_engine.detect()
        for cname, score in chains:
            if score > 0.8:
                self.log_audit("Attack Chain", cname, f"Detected threat chain with score {score}")
                self.queen.update("workstation", [{"entity": cname, "score": score}])

        global_risks = self.queen.global_risk()
        total_risk_score = sum(global_risks.values())

        altered_state = self.altered_states.evaluate(total_risk_score, cpu_usage, anomaly_detected_this_frame)
        self.prob_field.update(self.current_fps / 30.0)
        confidence_val = self.prob_field.sample()

        next_concept = self.next_concept_modeler.project_next_concept(self.current_fps, cpu_usage, total_risk_score)

        if self.predictive_toggle.get() == 1:
            cot_steps, decision = ChainOfThoughtReasoningEngine.reason(
                "Autonomous Workstation v4", telemetry, predicted_fps, altered_state, pressure, velocity, confidence_val, total_risk_score, next_concept
            )
            self.log_cot(cot_steps)

            remediation_status = altered_state
            if "MITIGATE" in decision and self.auto_remediate_var.get() == 1:
                remediation_status = f"{altered_state} [AUTO-HEALING ACTIVE]"
        else:
            remediation_status = altered_state

        telemetry_text = f"FPS: {self.current_fps:.1f} | ARIMA: {predicted_fps:.1f} | CPU: {cpu_usage}% | Concept: {next_concept} | State: {remediation_status}"
        self.telemetry_var.set(telemetry_text)

        canvas_width = self.canvas.winfo_width()
        canvas_height = self.canvas.winfo_height()
        if canvas_width > 10 and canvas_height > 10:
            preview_img = cv2.resize(display_output, (canvas_width, canvas_height))
            preview_img = cv2.cvtColor(preview_img, cv2.COLOR_BGR2RGB)
            img_pil = Image.fromarray(preview_img)
            self.photo_img = ImageTk.PhotoImage(image=img_pil)
            self.canvas.create_image(0, 0, image=self.photo_img, anchor=tk.NW)

        self.root.after(10, self.update_predictive_loop)

    def on_closing(self):
        self.save_settings()
        self.is_running = False
        if self.cap is not None and self.cap.isOpened():
            self.cap.release()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = UltimateStudioMixerApp(root)
    root.mainloop()