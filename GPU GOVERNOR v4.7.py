#!/usr/bin/env python3
# ============================================================
# GPU GOVERNOR v5.4 — NVML Fixed, Persistent Settings on Reboot,
# View-All Settings, AI-Only Apply, FLOP Governor, VRAM Stress,
# Curve Visualizer, Factory Reset, Live Gauges, Overdrive Slider
# ============================================================

import sys
import time
import json
import signal
import threading
import os
from dataclasses import dataclass
from typing import Callable, Optional, List

import torch
import pynvml
from PyQt5 import QtWidgets, QtCore, QtGui

# ============================================================
# Hardcoded defaults (manual profile)
# ============================================================

HC_POWER_LIMIT_W = 280
HC_TEMP_LIMIT_C = 83
HC_FLOP_LIMIT = 5e12  # 5 TFLOP/s

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "governor_settings.json")

# ============================================================
# NVML / GPU introspection (AI profile)
# ============================================================

NVML_INIT = False
NVML_DEVICE = None
NVML_LOCK = threading.Lock()

def nvml_init():
    global NVML_INIT, NVML_DEVICE
    with NVML_LOCK:
        if NVML_INIT:
            return
        try:
            pynvml.nvmlInit()
            NVML_DEVICE = pynvml.nvmlDeviceGetHandleByIndex(0)
            NVML_INIT = True
        except Exception as e:
            print(f"[NVML] Init failed: {e}")
            NVML_INIT = False
            NVML_DEVICE = None

def nvml_shutdown():
    global NVML_INIT
    with NVML_LOCK:
        if not NVML_INIT:
            return
        try:
            pynvml.nvmlShutdown()
        except Exception as e:
            print(f"[NVML] Shutdown failed: {e}")
        NVML_INIT = False

def _safe_nvml_name(h):
    try:
        name = pynvml.nvmlDeviceGetName(h)
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="ignore")
        return str(name)
    except Exception as e:
        print(f"[NVML] Name read failed: {e}")
        return "Unknown"

def get_gpu_telemetry():
    nvml_init()
    if not NVML_INIT or NVML_DEVICE is None:
        return {
            "name": "Unknown",
            "temp": 0,
            "power": 0.0,
            "core_clock": 0,
            "mem_clock": 0,
            "gpu_util": 0,
            "mem_util": 0,
        }
    h = NVML_DEVICE
    try:
        name = _safe_nvml_name(h)
        temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
        power = pynvml.nvmlDeviceGetPowerUsage(h) / 1000.0
        core_clock = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_GRAPHICS)
        mem_clock = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_MEM)
        util = pynvml.nvmlDeviceGetUtilizationRates(h)
        return {
            "name": name,
            "temp": temp,
            "power": power,
            "core_clock": core_clock,
            "mem_clock": mem_clock,
            "gpu_util": util.gpu,
            "mem_util": util.memory,
        }
    except Exception as e:
        print(f"[NVML] Telemetry failed: {e}")
        return {
            "name": "Unknown",
            "temp": 0,
            "power": 0.0,
            "core_clock": 0,
            "mem_clock": 0,
            "gpu_util": 0,
            "mem_util": 0,
        }

def get_default_power_limit_w():
    nvml_init()
    if not NVML_INIT or NVML_DEVICE is None:
        return HC_POWER_LIMIT_W
    h = NVML_DEVICE
    try:
        return pynvml.nvmlDeviceGetPowerManagementDefaultLimit(h) / 1000.0
    except Exception as e:
        print(f"[NVML] Default power limit failed: {e}")
        return HC_POWER_LIMIT_W

def get_thermal_cap_c():
    nvml_init()
    if not NVML_INIT or NVML_DEVICE is None:
        return HC_TEMP_LIMIT_C + 5
    h = NVML_DEVICE
    try:
        temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
        return max(HC_TEMP_LIMIT_C, temp + 10)
    except Exception as e:
        print(f"[NVML] Thermal cap failed: {e}")
        return HC_TEMP_LIMIT_C + 5

def estimate_fp32_flops_per_sec():
    nvml_init()
    if not NVML_INIT or NVML_DEVICE is None:
        return HC_FLOP_LIMIT
    h = NVML_DEVICE
    try:
        core_clock_mhz = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_GRAPHICS)
        sm_count = 80
        fp32_cores_per_sm = 64
        freq_hz = core_clock_mhz * 1e6
        cores = sm_count * fp32_cores_per_sm
        flops = cores * freq_hz * 2
        return max(HC_FLOP_LIMIT, min(flops, 5e13))
    except Exception as e:
        print(f"[NVML] FP32 estimate failed: {e}")
        return HC_FLOP_LIMIT

def set_power_limit_w(watts: int):
    nvml_init()
    if not NVML_INIT or NVML_DEVICE is None:
        print("[NVML] Power limit set skipped (NVML not initialized)")
        return
    h = NVML_DEVICE
    try:
        pynvml.nvmlDeviceSetPowerManagementLimit(h, int(watts * 1000))
        print(f"[NVML] Power limit set to {watts} W")
    except Exception as e:
        print(f"[NVML] Failed to set power limit: {e}")

# ============================================================
# FLOP Governor
# ============================================================

class FlopGovernor:
    def __init__(self, target_flops_per_sec: float):
        self.target = float(target_flops_per_sec)
        self.bucket = float(target_flops_per_sec)
        self.last_refill = time.time()
        self.lock = threading.Lock()

        self.total_flops = 0.0
        self.last_second_flops = 0.0
        self.last_second_timestamp = time.time()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed >= 1.0:
            self.bucket = self.target
            self.last_refill = now
            self.last_second_flops = 0.0
            self.last_second_timestamp = now

    def register(self, flops: float):
        flops = float(flops)
        with self.lock:
            self._refill()

            self.total_flops += flops
            self.last_second_flops += flops

            if self.bucket <= 0.0 and self.target > 0.0:
                deficit = abs(self.bucket)
                sleep_time = deficit / self.target
                if sleep_time > 0.0:
                    time.sleep(sleep_time)
                self._refill()

            self.bucket -= flops

    def run_op(self, op: Callable[[], torch.Tensor], flops_estimate: float):
        self.register(flops_estimate)
        return op()

    def set_target(self, new_target_flops_per_sec: float):
        with self.lock:
            self.target = float(new_target_flops_per_sec)
            self.bucket = self.target
            self.last_refill = time.time()
            self.last_second_flops = 0.0
            self.last_second_timestamp = self.last_refill
        print(f"[FLOP-GOV] New FLOP limit: {self.target:.3e} FLOP/s")

# ============================================================
# VRAM Stress Tester
# ============================================================

@dataclass
class VramStressConfig:
    duration_s: int = 120
    matrix_n: int = 4096
    cap_util: int = 90

class VramStressTester:
    def __init__(self, cfg: VramStressConfig, flop_gov: Optional[FlopGovernor] = None):
        self.cfg = cfg
        self.flop_gov = flop_gov
        self.stop_flag = False

    def _estimate_matmul_flops(self, n: int) -> float:
        return 2.0 * (n ** 3)

    def run(self):
        if not torch.cuda.is_available():
            print("[VRAM-STRESS] CUDA not available, skipping")
            return

        device = torch.device("cuda")
        n = self.cfg.matrix_n

        x = torch.randn(n, n, device=device)
        y = torch.randn(n, n, device=device)

        flops_per_matmul = self._estimate_matmul_flops(n)
        start = time.time()

        print(f"[VRAM-STRESS] Starting, N={n}, FLOPs/op={flops_per_matmul:.3e}")

        while not self.stop_flag and (time.time() - start) < self.cfg.duration_s:
            def op():
                return torch.matmul(x, y)

            if self.flop_gov is not None:
                _ = self.flop_gov.run_op(op, flops_per_matmul)
            else:
                _ = op()

            telem = get_gpu_telemetry()
            flops_s = self.flop_gov.last_second_flops if self.flop_gov else 0.0

            print(
                f"[VRAM-STRESS] t={int(time.time()-start)}s "
                f"temp={telem['temp']}C power={telem['power']:.1f}W "
                f"util={telem['gpu_util']}% FLOPs/s={flops_s:.3e}"
            )

            time.sleep(0.05)

        print("[VRAM-STRESS] Completed")

    def stop(self):
        self.stop_flag = True

# ============================================================
# Curve Visualizer
# ============================================================

@dataclass
class CurveSample:
    timestamp: float
    temp: float
    power: float
    core_clock: float
    mem_clock: float
    gpu_util: float

class CurveVisualizer:
    def __init__(self):
        self.samples: List[CurveSample] = []

    def sample(self):
        telem = get_gpu_telemetry()
        s = CurveSample(
            timestamp=time.time(),
            temp=telem["temp"],
            power=telem["power"],
            core_clock=telem["core_clock"],
            mem_clock=telem["mem_clock"],
            gpu_util=telem["gpu_util"],
        )
        self.samples.append(s)

    def export_json(self, path: str):
        data = [
            {
                "t": s.timestamp,
                "temp": s.temp,
                "power": s.power,
                "core_clock": s.core_clock,
                "mem_clock": s.mem_clock,
                "gpu_util": s.gpu_util,
            }
            for s in self.samples
        ]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[CURVE] Exported {len(self.samples)} samples to {path}")
        except Exception as e:
            print(f"[CURVE] Export failed: {e}")

# ============================================================
# Factory Reset
# ============================================================

class FactoryReset:
    def __init__(self):
        self._default_power = None

    def snapshot_defaults(self):
        self._default_power = get_default_power_limit_w()
        print(f"[FACTORY-RESET] Snapshot default power={self._default_power:.1f} W")

    def restore(self):
        if self._default_power is not None:
            print(f"[FACTORY-RESET] Restoring power limit to {self._default_power:.1f} W")
            set_power_limit_w(int(self._default_power))
        else:
            print("[FACTORY-RESET] No snapshot, skipping")

# ============================================================
# Governor core (profiles, AI-only apply, persistent settings)
# ============================================================

@dataclass
class GovernorConfig:
    power_limit_w: int
    temp_limit_c: int
    flop_limit: float
    poll_interval_s: float = 1.0

class GpuGovernor:
    def __init__(self):
        ai_power = int(get_default_power_limit_w())
        ai_temp_cap = int(get_thermal_cap_c())
        ai_flops = estimate_fp32_flops_per_sec()

        self.hc_cfg = GovernorConfig(
            power_limit_w=HC_POWER_LIMIT_W,
            temp_limit_c=HC_TEMP_LIMIT_C,
            flop_limit=HC_FLOP_LIMIT,
            poll_interval_s=1.0,
        )

        self.ai_cfg = GovernorConfig(
            power_limit_w=ai_power,
            temp_limit_c=ai_temp_cap - 5,
            flop_limit=ai_flops,
            poll_interval_s=1.0,
        )

        self.cfg = GovernorConfig(
            power_limit_w=self.ai_cfg.power_limit_w,
            temp_limit_c=self.ai_cfg.temp_limit_c,
            flop_limit=self.ai_cfg.flop_limit,
            poll_interval_s=1.0,
        )

        self.profile_mode = "AI"

        self.running = False
        self.thread: Optional[threading.Thread] = None

        self.flop_gov = FlopGovernor(self.cfg.flop_limit)
        self.vram_stress = VramStressTester(
            VramStressConfig(duration_s=120, matrix_n=4096, cap_util=90),
            flop_gov=self.flop_gov,
        )
        self.curve_vis = CurveVisualizer()
        self.factory_reset = FactoryReset()
        self.factory_reset.snapshot_defaults()

        self.gui_lock = threading.Lock()
        self.gui_flop_slider_value = self.cfg.flop_limit

        self.pending_power = self.cfg.power_limit_w
        self.pending_flops = self.cfg.flop_limit
        self.pending_temp = self.cfg.temp_limit_c

        self._load_persistent_settings()

    # ---------- persistence ----------

    def _load_persistent_settings(self):
        if not os.path.isfile(SETTINGS_PATH):
            print("[PERSIST] No settings file, using AI defaults")
            return
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            mode = data.get("profile_mode", "AI")
            power = int(data.get("power_limit_w", self.cfg.power_limit_w))
            temp = int(data.get("temp_limit_c", self.cfg.temp_limit_c))
            flops = float(data.get("flop_limit", self.cfg.flop_limit))

            if mode not in ("AI", "HC"):
                mode = "AI"

            self.profile_mode = mode
            self.cfg.power_limit_w = power
            self.cfg.temp_limit_c = temp
            self.cfg.flop_limit = flops
            self.flop_gov.set_target(self.cfg.flop_limit)

            self.pending_power = power
            self.pending_temp = temp
            self.pending_flops = flops

            print(f"[PERSIST] Loaded settings: mode={mode} "
                  f"power={power}W temp={temp}C flops={flops:.3e}")
        except Exception as e:
            print(f"[PERSIST] Load failed: {e}")

    def _save_persistent_settings(self):
        data = {
            "profile_mode": self.profile_mode,
            "power_limit_w": int(self.cfg.power_limit_w),
            "temp_limit_c": int(self.cfg.temp_limit_c),
            "flop_limit": float(self.cfg.flop_limit),
        }
        try:
            with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[PERSIST] Saved settings to {SETTINGS_PATH}")
        except Exception as e:
            print(f"[PERSIST] Save failed: {e}")

    # ---------- profile / GUI ----------

    def set_profile_mode(self, mode: str):
        if mode not in ("AI", "HC"):
            return
        self.profile_mode = mode
        if mode == "AI":
            base = self.ai_cfg
        else:
            base = self.hc_cfg
        self.pending_power = base.power_limit_w
        self.pending_temp = base.temp_limit_c
        self.pending_flops = base.flop_limit
        print(f"[PROFILE] {mode} base pending: "
              f"power={self.pending_power}W temp={self.pending_temp}C flops={self.pending_flops:.3e}")

    def apply_ai_safe(self):
        self.cfg.power_limit_w = int(self.pending_power)
        self.cfg.temp_limit_c = int(self.pending_temp)
        self.cfg.flop_limit = float(self.pending_flops)
        self.flop_gov.set_target(self.cfg.flop_limit)
        self.gui_flop_slider_value = self.cfg.flop_limit
        set_power_limit_w(self.cfg.power_limit_w)
        self._save_persistent_settings()
        print(f"[AI-APPLY] Applied: power={self.cfg.power_limit_w}W "
              f"temp={self.cfg.temp_limit_c}C flops={self.cfg.flop_limit:.3e}")

    def gui_set_pending_flops(self, new_flops: float):
        with self.gui_lock:
            self.pending_flops = float(new_flops)

    def gui_get_pending_flops(self) -> float:
        with self.gui_lock:
            return self.pending_flops

    def gui_set_pending_power(self, new_power_w: int):
        self.pending_power = int(new_power_w)

    def gui_set_pending_temp(self, new_temp_c: int):
        self.pending_temp = int(new_temp_c)

    # ---------- governor loop ----------

    def _safe_tune_loop(self):
        telem = get_gpu_telemetry()
        print(
            f"[GOVERNOR] Starting for GPU {telem['name']} "
            f"profile={self.profile_mode} "
            f"power_limit={self.cfg.power_limit_w} W "
            f"temp_limit={self.cfg.temp_limit_c} C "
            f"default FLOPs={self.cfg.flop_limit:.3e}"
        )
        set_power_limit_w(self.cfg.power_limit_w)

        start = time.time()
        while self.running:
            telem = get_gpu_telemetry()
            self.curve_vis.sample()

            temp = telem["temp"]
            power = telem["power"]
            util = telem["gpu_util"]
            flops_s = self.flop_gov.last_second_flops

            print(
                f"[GOVERNOR] t={int(time.time()-start)}s "
                f"temp={temp}C power={power:.1f}W util={util}% "
                f"FLOPs/s={flops_s:.3e} target={self.cfg.flop_limit:.3e} "
                f"profile={self.profile_mode}"
            )

            if temp > self.cfg.temp_limit_c:
                print("[GOVERNOR] Thermal limit exceeded, backing off power")
                new_limit = max(150, self.cfg.power_limit_w - 20)
                self.cfg.power_limit_w = new_limit
                set_power_limit_w(new_limit)
                self._save_persistent_settings()

            time.sleep(self.cfg.poll_interval_s)

        print("[GOVERNOR] Loop exiting")

    def start(self):
        if self.running:
            print("[GOVERNOR] Already running")
            return
        self.running = True
        self.thread = threading.Thread(target=self._safe_tune_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread is not None:
            self.thread.join(timeout=5.0)
        self.factory_reset.restore()
        nvml_shutdown()
        print("[GOVERNOR] Stopped, factory defaults restored")

    def run_vram_stress(self):
        self.vram_stress.run()

    def export_curve(self, path: str):
        self.curve_vis.export_json(path)

# ============================================================
# GUI — view all, AI-only apply, live gauges, overdrive slider
# ============================================================

class ColorSlider(QtWidgets.QSlider):
    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.overdrive_threshold = 40

    def set_overdrive_threshold(self, v: int):
        self.overdrive_threshold = v

    def update_color(self):
        v = self.value()
        min_v = self.minimum()
        max_v = self.maximum()
        ratio = (v - min_v) / max(1, (max_v - min_v))

        if v >= self.overdrive_threshold:
            color = QtGui.QColor(255, 0, 0)
        else:
            g = int(255 * ratio)
            r = int(255 * (1 - ratio))
            color = QtGui.QColor(r, g, 0)

        style = f"""
        QSlider::groove:horizontal {{
            height: 8px;
            background: #ffffff;
        }}
        QSlider::handle:horizontal {{
            background: {color.name()};
            border: 1px solid #444;
            width: 18px;
            margin: -5px 0;
            border-radius: 4px;
        }}
        """
        self.setStyleSheet(style)

    def setValue(self, v: int):
        super().setValue(v)
        self.update_color()

class GovernorGUI(QtWidgets.QWidget):
    def __init__(self, governor: GpuGovernor):
        super().__init__()
        self.gov = governor
        self._build_ui()
        self._start_telemetry_timer()

    def _build_ui(self):
        telem = get_gpu_telemetry()
        self.setWindowTitle(f"GPU Governor v5.4 — {telem['name']}")
        main_layout = QtWidgets.QVBoxLayout()

        self.lbl_gpu = QtWidgets.QLabel(f"GPU: {telem['name']}")
        main_layout.addWidget(self.lbl_gpu)

        gauges_group = QtWidgets.QGroupBox("Live Telemetry Gauges")
        gauges_layout = QtWidgets.QHBoxLayout()

        self.gauge_temp = QtWidgets.QProgressBar()
        self.gauge_temp.setRange(0, 100)
        self.gauge_temp.setFormat("Temp: %v °C")
        self.gauge_temp.setTextVisible(True)

        self.gauge_power = QtWidgets.QProgressBar()
        self.gauge_power.setRange(0, 500)
        self.gauge_power.setFormat("Power: %v W")
        self.gauge_power.setTextVisible(True)

        self.gauge_util = QtWidgets.QProgressBar()
        self.gauge_util.setRange(0, 100)
        self.gauge_util.setFormat("GPU Util: %v %")
        self.gauge_util.setTextVisible(True)

        self.gauge_flops = QtWidgets.QProgressBar()
        self.gauge_flops.setRange(0, 100)
        self.gauge_flops.setFormat("FLOPs: %v %")
        self.gauge_flops.setTextVisible(True)

        gauges_layout.addWidget(self.gauge_temp)
        gauges_layout.addWidget(self.gauge_power)
        gauges_layout.addWidget(self.gauge_util)
        gauges_layout.addWidget(self.gauge_flops)

        gauges_group.setLayout(gauges_layout)
        main_layout.addWidget(gauges_group)

        self.lbl_temp = QtWidgets.QLabel("Temp: - C")
        self.lbl_power = QtWidgets.QLabel("Power: - W")
        self.lbl_util = QtWidgets.QLabel("Util: - %")
        self.lbl_flops = QtWidgets.QLabel("FLOPs/s: -")
        main_layout.addWidget(self.lbl_temp)
        main_layout.addWidget(self.lbl_power)
        main_layout.addWidget(self.lbl_util)
        main_layout.addWidget(self.lbl_flops)

        profile_group = QtWidgets.QGroupBox("Profile (view only until AI apply)")
        profile_layout = QtWidgets.QHBoxLayout()
        self.radio_ai = QtWidgets.QRadioButton("AI (GPU-derived)")
        self.radio_hc = QtWidgets.QRadioButton("Hardcoded")

        if self.gov.profile_mode == "HC":
            self.radio_hc.setChecked(True)
        else:
            self.radio_ai.setChecked(True)

        self.radio_ai.toggled.connect(self._on_profile_changed)
        self.radio_hc.toggled.connect(self._on_profile_changed)
        profile_layout.addWidget(self.radio_ai)
        profile_layout.addWidget(self.radio_hc)
        profile_group.setLayout(profile_layout)
        main_layout.addWidget(profile_group)

        main_layout.addWidget(QtWidgets.QLabel(
            "Pending settings (will NOT change GPU until 'AI Safe Apply' is pressed):"
        ))

        self.spin_pending_power = QtWidgets.QSpinBox()
        self.spin_pending_power.setRange(150, 450)
        self.spin_pending_power.setValue(self.gov.pending_power)
        self.spin_pending_power.valueChanged.connect(self._on_pending_power_changed)
        main_layout.addWidget(QtWidgets.QLabel("Pending Power limit (W)"))
        main_layout.addWidget(self.spin_pending_power)

        self.spin_pending_temp = QtWidgets.QSpinBox()
        self.spin_pending_temp.setRange(60, 95)
        self.spin_pending_temp.setValue(self.gov.pending_temp)
        self.spin_pending_temp.valueChanged.connect(self._on_pending_temp_changed)
        main_layout.addWidget(QtWidgets.QLabel("Pending Temp limit (C)"))
        main_layout.addWidget(self.spin_pending_temp)

        self.slider_flops = ColorSlider(QtCore.Qt.Horizontal)
        self.slider_flops.setMinimum(5)
        self.slider_flops.setMaximum(50)
        self.slider_flops.set_overdrive_threshold(40)
        step = max(5, int(self.gov.pending_flops / 1e11))
        self.slider_flops.setValue(step)
        self.slider_flops.valueChanged.connect(self._on_pending_flops_changed)
        main_layout.addWidget(QtWidgets.QLabel(
            "Pending FLOP limit (x1e11 FLOP/s) — white→green→red (red = overdrive)"
        ))
        main_layout.addWidget(self.slider_flops)

        self.btn_ai_apply = QtWidgets.QPushButton("AI Safe Apply (commit pending settings)")
        self.btn_ai_apply.clicked.connect(self._on_ai_apply)
        main_layout.addWidget(self.btn_ai_apply)

        btn_start = QtWidgets.QPushButton("Start Governor")
        btn_stop = QtWidgets.QPushButton("Stop Governor")
        btn_stress = QtWidgets.QPushButton("Run VRAM Stress")
        btn_export = QtWidgets.QPushButton("Export Curve JSON")
        btn_reset = QtWidgets.QPushButton("Factory Reset")

        btn_start.clicked.connect(self._on_start)
        btn_stop.clicked.connect(self._on_stop)
        btn_stress.clicked.connect(self._on_stress)
        btn_export.clicked.connect(self._on_export)
        btn_reset.clicked.connect(self._on_reset)

        main_layout.addWidget(btn_start)
        main_layout.addWidget(btn_stop)
        main_layout.addWidget(btn_stress)
        main_layout.addWidget(btn_export)
        main_layout.addWidget(btn_reset)

        self.setLayout(main_layout)
        self.resize(520, 420)

    def _start_telemetry_timer(self):
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self._update_telemetry)
        self.timer.start(1000)

    # ---------- callbacks ----------

    def _on_profile_changed(self):
        if self.radio_ai.isChecked():
            self.gov.set_profile_mode("AI")
        elif self.radio_hc.isChecked():
            self.gov.set_profile_mode("HC")
        self.spin_pending_power.setValue(self.gov.pending_power)
        self.spin_pending_temp.setValue(self.gov.pending_temp)
        step = max(5, int(self.gov.pending_flops / 1e11))
        self.slider_flops.setValue(step)

    def _on_pending_power_changed(self, value):
        self.gov.gui_set_pending_power(value)

    def _on_pending_temp_changed(self, value):
        self.gov.gui_set_pending_temp(value)

    def _on_pending_flops_changed(self, value):
        target = value * 1e11
        self.gov.gui_set_pending_flops(target)
        self.slider_flops.update_color()

    def _on_ai_apply(self):
        self.gov.apply_ai_safe()

    def _on_start(self):
        self.gov.start()

    def _on_stop(self):
        self.gov.stop()

    def _on_stress(self):
        threading.Thread(target=self.gov.run_vram_stress, daemon=True).start()

    def _on_export(self):
        self.gov.export_curve("curve_v5_4.json")

    def _on_reset(self):
        self.gov.factory_reset.restore()

    def _update_telemetry(self):
        telem = get_gpu_telemetry()
        self.lbl_temp.setText(f"Temp: {telem['temp']} C")
        self.lbl_power.setText(f"Power: {telem['power']:.1f} W")
        self.lbl_util.setText(f"Util: {telem['gpu_util']} %")
        self.lbl_flops.setText(f"FLOPs/s: {self.gov.flop_gov.last_second_flops:.3e}")

        self.gauge_temp.setValue(int(telem['temp']))
        self.gauge_power.setValue(int(telem['power']))
        self.gauge_util.setValue(int(telem['gpu_util']))

        limit = max(1e9, self.gov.cfg.flop_limit)
        ratio = min(1.0, self.gov.flop_gov.last_second_flops / limit)
        self.gauge_flops.setValue(int(ratio * 100))

# ============================================================
# Entry point
# ============================================================

def handle_sigint(sig, frame):
    print("\n[MAIN] SIGINT received, shutting down")
    QtWidgets.QApplication.quit()

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    gov = GpuGovernor()

    app = QtWidgets.QApplication(sys.argv)
    gui = GovernorGUI(gov)
    gui.show()
    ret = app.exec_()

    gov.stop()
    sys.exit(ret)

if __name__ == "__main__":
    main()
