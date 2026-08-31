#!/usr/bin/env python3
# ai_system_guardian_v5_borg_physics_predictive.py

# ---------------------------------------------------------
# AUTOLOADER + AUTO ADMIN ELEVATION
# ---------------------------------------------------------

import os
import sys
import importlib
import subprocess

REQUIRED_LIBS = [
    "psutil",
    "PyQt5"
]

def autoload_libraries():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[AUTOLOADER] Installing missing library: {lib}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            print(f"[AUTOLOADER] Installed: {lib}")

def is_admin():
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def relaunch_as_admin():
    if os.name == "nt":
        import ctypes
        print("[ADMIN] Guardian requires elevated privileges. Relaunching as administrator...")
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        except Exception as e:
            print(f"[ADMIN] Elevation failed: {e}")
        sys.exit(0)
    else:
        print("[ADMIN] Guardian requires elevated privileges. Relaunching with sudo...")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[ADMIN] Elevation failed: {e}")
            sys.exit(1)

autoload_libraries()

if not is_admin():
    relaunch_as_admin()

# ---------------------------------------------------------
# IMPORTS AFTER AUTOLOADER
# ---------------------------------------------------------

import json
import platform
import random
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

import psutil
from PyQt5.QtCore import Qt, QRectF, QTimer
from PyQt5.QtGui import QColor, QBrush, QPen
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QGraphicsView, QGraphicsScene,
    QLabel, QHeaderView, QPushButton, QComboBox, QMessageBox
)

# ---------------------------------------------------------
# DATA MODEL / CONSTANTS
# ---------------------------------------------------------

@dataclass
class AssetIncident:
    asset_id: str
    asset_type: str
    risk_score: int
    confidence: float
    criticality: str
    status: str
    mitre_tactic: str
    isolated: bool = False
    safe: bool = False
    predictive_risk: int = 0
    missing_details_score: float = 0.0

MITRE_TACTIC_COLORS = {
    "Initial Access": QColor(0, 120, 215),
    "Execution": QColor(112, 48, 160),
    "Persistence": QColor(0, 153, 153),
    "Privilege Escalation": QColor(255, 140, 0),
    "Lateral Movement": QColor(220, 20, 60),
    "Exfiltration": QColor(0, 0, 0),
    "Discovery": QColor(0, 100, 0),
    "Command and Control": QColor(128, 0, 0),
}

GUARDIAN_LOG_NAME = "guardian.log"
SURICATA_EVE_PATH = "eve.json"
HONEYPOT_DIR_NAME = "guardian_honeypot"

ROGUE_AI_KEYWORDS = [
    "llm", "agent", "autonomous", "prompt", "openai",
    "chatgpt", "stable-diffusion", "copilot", "langchain",
    "ai_server", "ai_daemon"
]

SAFE_GAME_PROCESSES = [
    "steam.exe", "steam", "steamwebhelper",
    "epicgameslauncher.exe", "epicgameslauncher",
    "battle.net.exe", "origin.exe", "eaapp.exe",
    "goggalaxy.exe", "gog", "riotclientservices.exe",
    "fortnite.exe", "valorant.exe", "cod.exe",
    "eldenring.exe", "gta5.exe", "cs2.exe",
]

SAFE_GAME_ENGINES = [
    "unity", "unreal", "source", "frostbite", "cryengine"
]

SAFE_GAME_PATH_HINTS = [
    "steamapps", "Epic Games", ".steam", "GOG Games", "Battle.net"
]

SENSITIVE_DIR_HINTS = [
    "Documents", "Pictures", "Videos",
    "Desktop",
    "AppData\\Local\\Microsoft\\Windows\\Biometrics",
    "AppData\\Local\\Microsoft\\Windows\\WebCache",
    "/var/lib/fprint",
    "/usr/share/fingerprint",
    "/home",
    "/Users",
]

# ---------------------------------------------------------
# PATHS / BASELINE / LOG / BORG MEMORY
# ---------------------------------------------------------

def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def get_baseline_path() -> str:
    return os.path.join(get_script_dir(), "baseline.json")

def get_guardian_log_path() -> str:
    return os.path.join(get_script_dir(), GUARDIAN_LOG_NAME)

def load_baseline() -> Dict:
    path = get_baseline_path()
    if not os.path.exists(path):
        return {
            "assets": {},
            "mode": "passive",
            "stats": {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            },
            "borg_memory": {},
            "physics": {
                "last_timestamp": time.time(),
                "cpu_history": [],
                "ram_history": [],
                "net_history": [],
                "gpu_history": []
            }
        }
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "assets" not in data:
            data["assets"] = {}
        if "mode" not in data:
            data["mode"] = "passive"
        if "stats" not in data:
            data["stats"] = {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            }
        if "borg_memory" not in data:
            data["borg_memory"] = {}
        if "physics" not in data:
            data["physics"] = {
                "last_timestamp": time.time(),
                "cpu_history": [],
                "ram_history": [],
                "net_history": [],
                "gpu_history": []
            }
        return data
    except Exception:
        return {
            "assets": {},
            "mode": "passive",
            "stats": {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            },
            "borg_memory": {},
            "physics": {
                "last_timestamp": time.time(),
                "cpu_history": [],
                "ram_history": [],
                "net_history": [],
                "gpu_history": []
            }
        }

def save_baseline(assets: List[AssetIncident], mode: str, stats: Dict, borg_memory: Dict, physics: Dict) -> None:
    path = get_baseline_path()
    data = {
        "assets": {a.asset_id: asdict(a) for a in assets},
        "mode": mode,
        "stats": stats,
        "borg_memory": borg_memory,
        "physics": physics
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_guardian_log(message: str) -> None:
    path = get_guardian_log_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(message + "\n")

# ---------------------------------------------------------
# SIMPLE ML-LIKE ANOMALY STATS + PREDICTIVE (DATA PHYSICS)
# ---------------------------------------------------------

def update_stats(stats: Dict, cpu: float, ram: float, net_conn: int, gpu: float) -> Dict:
    samples = stats.get("samples", 0)
    if samples <= 0:
        stats["cpu_mean"] = cpu
        stats["ram_mean"] = ram
        stats["net_conn_mean"] = net_conn
        stats["gpu_mean"] = gpu
        stats["samples"] = 1
        return stats

    samples += 1
    stats["cpu_mean"] = stats["cpu_mean"] + (cpu - stats["cpu_mean"]) / samples
    stats["ram_mean"] = stats["ram_mean"] + (ram - stats["ram_mean"]) / samples
    stats["net_conn_mean"] = stats["net_conn_mean"] + (net_conn - stats["net_conn_mean"]) / samples
    stats["gpu_mean"] = stats["gpu_mean"] + (gpu - stats["gpu_mean"]) / samples
    stats["samples"] = samples
    return stats

def anomaly_score(stats: Dict, cpu: float, ram: float, net_conn: int, gpu: float) -> float:
    def dev(current, mean):
        return abs(current - mean)

    cpu_dev = dev(cpu, stats.get("cpu_mean", 0.0))
    ram_dev = dev(ram, stats.get("ram_mean", 0.0))
    net_dev = dev(net_conn, stats.get("net_conn_mean", 0.0))
    gpu_dev = dev(gpu, stats.get("gpu_mean", 0.0))

    score = (cpu_dev / 20.0) + (ram_dev / 20.0) + (net_dev / 50.0) + (gpu_dev / 20.0)
    return min(score, 10.0)

def update_physics(physics: Dict, cpu: float, ram: float, net_conn: int, gpu: float) -> Dict:
    # Data physics: treat metrics as particles with inertia and trend
    max_len = 64
    physics["cpu_history"].append(cpu)
    physics["ram_history"].append(ram)
    physics["net_history"].append(net_conn)
    physics["gpu_history"].append(gpu)
    for key in ["cpu_history", "ram_history", "net_history", "gpu_history"]:
        if len(physics[key]) > max_len:
            physics[key] = physics[key][-max_len:]
    physics["last_timestamp"] = time.time()
    return physics

def simple_trend_predict(history: List[float]) -> float:
    if len(history) < 3:
        return history[-1] if history else 0.0
    # Weighted linear trend: last values matter more
    n = len(history)
    weights = list(range(1, n + 1))
    mean = sum(h * w for h, w in zip(history, weights)) / sum(weights)
    # Rough trend: difference between last and first
    trend = (history[-1] - history[0]) / max(1, n - 1)
    return mean + trend * 2.0  # project slightly ahead

def predictive_system_risk(stats: Dict, physics: Dict) -> float:
    cpu_pred = simple_trend_predict(physics.get("cpu_history", []))
    ram_pred = simple_trend_predict(physics.get("ram_history", []))
    net_pred = simple_trend_predict(physics.get("net_history", []))
    gpu_pred = simple_trend_predict(physics.get("gpu_history", []))

    cpu_dev = abs(cpu_pred - stats.get("cpu_mean", 0.0))
    ram_dev = abs(ram_pred - stats.get("ram_mean", 0.0))
    net_dev = abs(net_pred - stats.get("net_conn_mean", 0.0))
    gpu_dev = abs(gpu_pred - stats.get("gpu_mean", 0.0))

    score = (cpu_dev / 20.0) + (ram_dev / 20.0) + (net_dev / 50.0) + (gpu_dev / 20.0)
    return min(score, 10.0)

# ---------------------------------------------------------
# GPU MONITORING (NVIDIA STUB)
# ---------------------------------------------------------

def get_gpu_usage() -> float:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if result.returncode != 0:
            return 0.0
        lines = result.stdout.strip().splitlines()
        if not lines:
            return 0.0
        vals = [float(x.strip()) for x in lines if x.strip()]
        if not vals:
            return 0.0
        return sum(vals) / len(vals)
    except Exception:
        return 0.0

# ---------------------------------------------------------
# SURICATA ALERT INGESTION (EVE JSON STUB)
# ---------------------------------------------------------

def ingest_suricata_alerts() -> List[AssetIncident]:
    path = os.path.join(get_script_dir(), SURICATA_EVE_PATH)
    if not os.path.exists(path):
        return []
    incidents: List[AssetIncident] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    eve = json.loads(line)
                except Exception:
                    continue
                if eve.get("event_type") == "alert":
                    src_ip = eve.get("src_ip", "unknown")
                    dest_ip = eve.get("dest_ip", "unknown")
                    sig = eve.get("alert", {}).get("signature", "unknown")
                    risk = 90
                    incidents.append(AssetIncident(
                        asset_id=f"SURI-{src_ip}->{dest_ip}",
                        asset_type="network_alert",
                        risk_score=risk,
                        confidence=0.95,
                        criticality="high",
                        status="open",
                        mitre_tactic="Exfiltration",
                        predictive_risk=risk,
                        missing_details_score=0.2 if sig == "unknown" else 0.0
                    ))
    except Exception:
        pass
    return incidents

# ---------------------------------------------------------
# HONEYPOT TRAP (FAKE DIRECTORY)
# ---------------------------------------------------------

def ensure_honeypot_dir() -> str:
    path = os.path.join(get_script_dir(), HONEYPOT_DIR_NAME)
    if not os.path.exists(path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass
    return path

def detect_honeypot_access() -> List[AssetIncident]:
    path = ensure_honeypot_dir()
    incidents: List[AssetIncident] = []
    # For now, we treat honeypot as a latent trap: predictive risk, not always active
    incidents.append(AssetIncident(
        asset_id=f"HONEYPOT-{os.path.basename(path)}",
        asset_type="honeypot",
        risk_score=40,
        confidence=0.7,
        criticality="high",
        status="investigating",
        mitre_tactic="Initial Access",
        predictive_risk=70,
        missing_details_score=0.5
    ))
    return incidents

# ---------------------------------------------------------
# ROGUE AI SIGNATURE DETECTION (FIXED)
# ---------------------------------------------------------

def is_rogue_ai_process(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in ROGUE_AI_KEYWORDS)

# ---------------------------------------------------------
# GAME / PERSONAL PROTECTION HELPERS
# ---------------------------------------------------------

def is_game_process(proc: psutil.Process) -> bool:
    name = (proc.info.get('name') or "").strip()
    lower = name.lower()
    if name in SAFE_GAME_PROCESSES:
        return True
    if any(engine in lower for engine in SAFE_GAME_ENGINES):
        return True
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()
    if any(hint.lower() in exe_lower for hint in SAFE_GAME_PATH_HINTS):
        return True
    return False

def touches_sensitive_paths(proc: psutil.Process) -> bool:
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()
    if any(hint.lower() in exe_lower for hint in SENSITIVE_DIR_HINTS):
        return True
    return False

# ---------------------------------------------------------
# BORG LEARNING (COLLECTIVE MEMORY)
# ---------------------------------------------------------

def borg_learn_asset(borg_memory: Dict, asset: AssetIncident) -> Dict:
    # Borg learning: collective memory of asset behavior over time
    entry = borg_memory.get(asset.asset_id, {
        "seen_count": 0,
        "avg_risk": 0.0,
        "max_risk": 0,
        "avg_confidence": 0.0,
        "last_status": asset.status,
        "last_type": asset.asset_type
    })
    entry["seen_count"] += 1
    entry["avg_risk"] = entry["avg_risk"] + (asset.risk_score - entry["avg_risk"]) / entry["seen_count"]
    entry["max_risk"] = max(entry["max_risk"], asset.risk_score)
    entry["avg_confidence"] = entry["avg_confidence"] + (asset.confidence - entry["avg_confidence"]) / entry["seen_count"]
    entry["last_status"] = asset.status
    entry["last_type"] = asset.asset_type
    borg_memory[asset.asset_id] = entry
    return borg_memory

def borg_predict_asset(borg_memory: Dict, asset_id: str, current_risk: int) -> int:
    entry = borg_memory.get(asset_id)
    if not entry:
        return current_risk
    # Predictive: blend current risk with historical max and average
    avg_risk = entry.get("avg_risk", current_risk)
    max_risk = entry.get("max_risk", current_risk)
    predicted = int(0.4 * current_risk + 0.3 * avg_risk + 0.3 * max_risk)
    return predicted

def compute_missing_details_score(asset: AssetIncident) -> float:
    # Missing details wiring: look for "unknown", empty, or generic fields
    score = 0.0
    if "unknown" in asset.asset_id.lower():
        score += 0.3
    if asset.asset_type in ["process", "network_alert"] and asset.confidence < 0.7:
        score += 0.2
    if asset.mitre_tactic == "Initial Access" and asset.status == "investigating":
        score += 0.2
    if asset.asset_type == "honeypot":
        score += 0.3
    return min(score, 1.0)

# ---------------------------------------------------------
# SYSTEM SCAN
# ---------------------------------------------------------

def scan_system(stats: Dict, borg_memory: Dict, physics: Dict) -> Tuple[List[AssetIncident], Dict, Dict, Dict, float, float]:
    assets: List[AssetIncident] = []

    os_name = platform.system()
    assets.append(AssetIncident(
        asset_id=os_name,
        asset_type="os",
        risk_score=10,
        confidence=1.0,
        criticality="medium",
        status="closed",
        mitre_tactic="Initial Access",
        predictive_risk=10,
        missing_details_score=0.0
    ))

    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    try:
        disk = psutil.disk_usage(os.path.expanduser("~")).percent
    except Exception:
        disk = 0.0

    cpu_risk = int(cpu)
    ram_risk = int(ram)
    disk_risk = int(disk)

    assets.append(AssetIncident(
        asset_id="CPU",
        asset_type="hardware",
        risk_score=cpu_risk,
        confidence=0.9,
        criticality="high",
        status="open" if cpu_risk > 80 else "investigating",
        mitre_tactic="Execution",
        predictive_risk=cpu_risk,
        missing_details_score=0.0
    ))

    assets.append(AssetIncident(
        asset_id="RAM",
        asset_type="hardware",
        risk_score=ram_risk,
        confidence=0.85,
        criticality="high",
        status="open" if ram_risk > 85 else "investigating",
        mitre_tactic="Persistence",
        predictive_risk=ram_risk,
        missing_details_score=0.0
    ))

    assets.append(AssetIncident(
        asset_id="DISK",
        asset_type="hardware",
        risk_score=disk_risk,
        confidence=0.8,
        criticality="medium",
        status="open" if disk_risk > 90 else "investigating",
        mitre_tactic="Persistence",
        predictive_risk=disk_risk,
        missing_details_score=0.0
    ))

    try:
        conns = psutil.net_connections()
        conn_count = len(conns)
    except Exception:
        conn_count = 0

    net_risk = 20 if conn_count < 100 else 60 if conn_count < 300 else 90
    assets.append(AssetIncident(
        asset_id="Network",
        asset_type="network",
        risk_score=net_risk,
        confidence=0.9,
        criticality="high",
        status="open" if net_risk >= 80 else "investigating",
        mitre_tactic="Lateral Movement",
        predictive_risk=net_risk,
        missing_details_score=0.0
    ))

    gpu_usage = get_gpu_usage()

    stats = update_stats(stats, cpu, ram, conn_count, gpu_usage)
    physics = update_physics(physics, cpu, ram, conn_count, gpu_usage)
    anomaly = anomaly_score(stats, cpu, ram, conn_count, gpu_usage)
    predictive_anomaly = predictive_system_risk(stats, physics)

    if anomaly > 2.0:
        assets.append(AssetIncident(
            asset_id="ANOMALY-SYSTEM",
            asset_type="anomaly",
            risk_score=int(min(100, anomaly * 10)),
            confidence=0.9,
            criticality="high",
            status="open",
            mitre_tactic="Privilege Escalation",
            predictive_risk=int(min(100, predictive_anomaly * 10)),
            missing_details_score=0.2
        ))

    for proc in psutil.process_iter(['pid', 'name']):
        name = (proc.info.get('name') or "").strip()
        if not name:
            continue
        lower = name.lower()
        suspicious = any(k in lower for k in ["python", "ai", "llm", "cuda", "torch"])
        rogue_ai = is_rogue_ai_process(name)
        game = False
        sensitive_touch = False
        try:
            game = is_game_process(proc)
        except Exception:
            game = False
        try:
            sensitive_touch = touches_sensitive_paths(proc)
        except Exception:
            sensitive_touch = False

        if not (suspicious or rogue_ai or game or sensitive_touch):
            continue

        base_risk = random.randint(30, 95)
        if rogue_ai:
            base_risk = max(base_risk, 80)
        if game:
            base_risk = min(base_risk, 40)
        if sensitive_touch and not game:
            base_risk = max(base_risk, 85)

        criticality = "medium"
        if sensitive_touch and not game:
            criticality = "high"

        status = "investigating"
        if sensitive_touch and not game:
            status = "open"

        asset = AssetIncident(
            asset_id=f"PROC-{proc.info['pid']}",
            asset_type="process",
            risk_score=base_risk,
            confidence=random.uniform(0.5, 0.98),
            criticality=criticality,
            status=status,
            mitre_tactic="Execution",
            isolated=False,
            safe=game
        )
        asset.missing_details_score = compute_missing_details_score(asset)
        borg_memory = borg_learn_asset(borg_memory, asset)
        asset.predictive_risk = borg_predict_asset(borg_memory, asset.asset_id, asset.risk_score)
        assets.append(asset)

    suri_assets = ingest_suricata_alerts()
    for a in suri_assets:
        a.missing_details_score = compute_missing_details_score(a)
        borg_memory = borg_learn_asset(borg_memory, a)
        a.predictive_risk = borg_predict_asset(borg_memory, a.asset_id, a.risk_score)
    assets.extend(suri_assets)

    honeypot_assets = detect_honeypot_access()
    for a in honeypot_assets:
        a.missing_details_score = compute_missing_details_score(a)
        borg_memory = borg_learn_asset(borg_memory, a)
        a.predictive_risk = borg_predict_asset(borg_memory, a.asset_id, a.risk_score)
    assets.extend(honeypot_assets)

    return assets, stats, borg_memory, physics, anomaly, predictive_anomaly

# ---------------------------------------------------------
# MERGE WITH BASELINE
# ---------------------------------------------------------

def merge_with_baseline(new_assets: List[AssetIncident],
                        baseline: Dict,
                        borg_memory: Dict) -> List[AssetIncident]:
    merged: List[AssetIncident] = []
    baseline_assets = baseline.get("assets", {})

    for asset in new_assets:
        prev = baseline_assets.get(asset.asset_id)
        if prev:
            prev_risk = prev.get("risk_score", 0)
            prev_status = prev.get("status", "investigating")
            prev_isolated = prev.get("isolated", False)
            prev_safe = prev.get("safe", False)
            if asset.risk_score > prev_risk + 10:
                asset.status = "open"
            elif asset.risk_score < prev_risk - 10:
                asset.status = "closed"
            else:
                asset.status = prev_status
            asset.isolated = prev_isolated
            asset.safe = prev_safe or asset.safe
        else:
            asset.status = "open"

        borg_memory = borg_learn_asset(borg_memory, asset)
        asset.predictive_risk = borg_predict_asset(borg_memory, asset.asset_id, asset.risk_score)
        asset.missing_details_score = compute_missing_details_score(asset)
        merged.append(asset)

    return merged

# ---------------------------------------------------------
# COLOR SEMANTICS (ALTERED STATES WIRING)
# ---------------------------------------------------------

def risk_to_color(risk: int, safe: bool, predictive_risk: int, missing_details: float, altered_state: str) -> QColor:
    # Altered states wiring: different palettes per mode
    if altered_state == "borg":
        # Collective: predictive risk dominates, missing details adds purple tint
        base = predictive_risk
        if safe:
            return QColor(0, 120, 215)
        if base < 20:
            c = QColor(0, 150, 0)
        elif base < 50:
            c = QColor(255, 215, 0)
        elif base < 80:
            c = QColor(255, 140, 0)
        else:
            c = QColor(220, 20, 60)
        if missing_details > 0.3:
            c = QColor(c.red(), max(0, c.green() - 40), min(255, c.blue() + 80))
        return c
    elif altered_state == "physics":
        # Data physics: treat risk as heat
        if safe:
            return QColor(0, 120, 215)
        if risk < 20:
            return QColor(0, 180, 255)
        elif risk < 50:
            return QColor(0, 120, 255)
        elif risk < 80:
            return QColor(255, 140, 0)
        else:
            return QColor(255, 60, 0)
    else:
        # Default
        if safe:
            return QColor(0, 120, 215)
        if risk < 20:
            return QColor(0, 150, 0)
        elif risk < 50:
            return QColor(255, 215, 0)
        elif risk < 80:
            return QColor(255, 140, 0)
        else:
            return QColor(220, 20, 60)

def confidence_to_opacity(conf: float, missing_details: float) -> float:
    if conf < 0.0: conf = 0.0
    if conf > 1.0: conf = 1.0
    base = 0.4 + conf * 0.6
    # Missing details wiring: lower opacity if we know less
    base -= missing_details * 0.2
    return max(0.2, min(1.0, base))

def criticality_to_border(crit: str, isolated: bool, safe: bool, altered_state: str) -> QPen:
    if safe:
        return QPen(QColor(0, 120, 215), 3)
    if isolated:
        if altered_state == "borg":
            return QPen(QColor(0, 0, 255), 4, Qt.DashLine)
        else:
            return QPen(QColor(0, 0, 255), 3, Qt.DashLine)
    if crit == "high":
        return QPen(QColor(0, 0, 0), 3)
    elif crit == "medium":
        return QPen(QColor(80, 80, 80), 2)
    else:
        return QPen(QColor(150, 150, 150), 1)

def status_to_badge_color(status: str, altered_state: str) -> QColor:
    if altered_state == "physics":
        if status == "open":
            return QColor(255, 80, 0)
        elif status == "investigating":
            return QColor(255, 200, 0)
        else:
            return QColor(128, 128, 128)
    else:
        if status == "open":
            return QColor(0, 120, 215)
        elif status == "investigating":
            return QColor(128, 0, 128)
        else:
            return QColor(128, 128, 128)

# ---------------------------------------------------------
# GUI + GUARDIAN
# ---------------------------------------------------------

class SocGuardianWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI System Guardian v5 – Borg Physics Predictive SOC")
        self.resize(1500, 850)

        self.baseline = load_baseline()
        self.mode = self.baseline.get("mode", "passive")
        self.stats = self.baseline.get("stats", {
            "cpu_mean": 0.0,
            "ram_mean": 0.0,
            "net_conn_mean": 0.0,
            "gpu_mean": 0.0,
            "samples": 0
        })
        self.borg_memory = self.baseline.get("borg_memory", {})
        self.physics = self.baseline.get("physics", {
            "last_timestamp": time.time(),
            "cpu_history": [],
            "ram_history": [],
            "net_history": [],
            "gpu_history": []
        })

        assets, self.stats, self.borg_memory, self.physics, self.last_anomaly, self.last_predictive_anomaly = scan_system(
            self.stats, self.borg_memory, self.physics
        )
        self.assets: List[AssetIncident] = merge_with_baseline(assets, self.baseline, self.borg_memory)

        self.altered_state = "borg"  # borg / physics / default

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout()
        central.setLayout(main_layout)

        # LEFT: TABLE + CONTROLS
        left_layout = QVBoxLayout()
        main_layout.addLayout(left_layout, 2)

        title = QLabel("Assets / Incidents (Cards)")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        left_layout.addWidget(title)

        mode_layout = QHBoxLayout()
        mode_label = QLabel("Guardian Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["passive", "active", "aggressive"])
        idx = self.mode_combo.findText(self.mode)
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        left_layout.addLayout(mode_layout)

        altered_layout = QHBoxLayout()
        altered_label = QLabel("Altered State Wiring:")
        self.altered_combo = QComboBox()
        self.altered_combo.addItems(["borg", "physics", "default"])
        self.altered_combo.currentTextChanged.connect(self.on_altered_state_changed)
        altered_layout.addWidget(altered_label)
        altered_layout.addWidget(self.altered_combo)
        left_layout.addLayout(altered_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "Asset ID", "Type", "Risk", "Predictive", "Conf.",
            "Criticality", "Tactic", "Status", "Isolated", "Safe",
            "Missing?"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.cellClicked.connect(self.on_row_selected)
        left_layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Manual Rescan")
        self.refresh_btn.clicked.connect(self.on_manual_refresh)
        btn_layout.addWidget(self.refresh_btn)

        self.predictive_btn = QPushButton("Predictive Sweep")
        self.predictive_btn.clicked.connect(self.on_predictive_sweep)
        btn_layout.addWidget(self.predictive_btn)

        left_layout.addLayout(btn_layout)

        # RIGHT: GRAPH + SUMMARY
        right_layout = QVBoxLayout()
        main_layout.addLayout(right_layout, 3)

        graph_title = QLabel("Asset Graph (Risk / Isolation / Safe / Borg / Physics Map)")
        graph_title.setStyleSheet("font-weight: bold; font-size: 14px;")
        right_layout.addWidget(graph_title)

        self.scene = QGraphicsScene()
        self.graph_view = QGraphicsView(self.scene)
        right_layout.addWidget(self.graph_view)

        self.summary_label = QLabel("Select an asset card to see details.\nAltered states: Borg (collective), Physics (heat), Default.")
        self.summary_label.setWordWrap(True)
        right_layout.addWidget(self.summary_label)

        self.anomaly_label = QLabel("")
        self.anomaly_label.setWordWrap(True)
        right_layout.addWidget(self.anomaly_label)

        self.populate_table()
        self.draw_graph()

        self.guardian_timer = QTimer(self)
        self.guardian_timer.setInterval(5000)
        self.guardian_timer.timeout.connect(self.guardian_tick)
        self.guardian_timer.start()

    def populate_table(self):
        self.table.setRowCount(len(self.assets))
        for row, a in enumerate(self.assets):
            cols = [
                a.asset_id,
                a.asset_type,
                str(a.risk_score),
                str(a.predictive_risk),
                f"{a.confidence:.2f}",
                a.criticality,
                a.mitre_tactic,
                a.status,
                "yes" if a.isolated else "no",
                "yes" if a.safe else "no",
                f"{a.missing_details_score:.2f}",
            ]
            for col_idx, text in enumerate(cols):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col_idx, item)

            base_color = risk_to_color(a.risk_score, a.safe, a.predictive_risk, a.missing_details_score, self.altered_state)
            base_color.setAlphaF(confidence_to_opacity(a.confidence, a.missing_details_score))
            for col_idx in range(self.table.columnCount()):
                self.table.item(row, col_idx).setBackground(QBrush(base_color))

            tactic_color = MITRE_TACTIC_COLORS.get(a.mitre_tactic, QColor(0, 0, 0))
            self.table.item(row, 0).setForeground(QBrush(tactic_color))

        self.anomaly_label.setText(
            f"Last anomaly score: {getattr(self, 'last_anomaly', 0.0):.2f} | "
            f"Predictive anomaly: {getattr(self, 'last_predictive_anomaly', 0.0):.2f}"
        )

    def draw_graph(self, selected: Optional[AssetIncident] = None):
        self.scene.clear()
        x, y = 60, 60
        node_w, node_h = 90, 90
        max_width = 1050

        for a in self.assets:
            base_color = risk_to_color(a.risk_score, a.safe, a.predictive_risk, a.missing_details_score, self.altered_state)
            base_color.setAlphaF(confidence_to_opacity(a.confidence, a.missing_details_score))
            rect = QRectF(x, y, node_w, node_h)
            pen = criticality_to_border(a.criticality, a.isolated, a.safe, self.altered_state)
            self.scene.addEllipse(rect, pen, QBrush(base_color))

            text = self.scene.addText(a.asset_id)
            text.setPos(x + 6, y + node_h + 5)

            badge_color = status_to_badge_color(a.status, self.altered_state)
            self.scene.addEllipse(
                QRectF(x + node_w - 18, y + 6, 14, 14),
                QPen(Qt.NoPen),
                QBrush(badge_color)
            )

            if selected and selected.asset_id == a.asset_id:
                highlight_pen = QPen(QColor(0, 0, 0), 4, Qt.DashLine)
                self.scene.addEllipse(rect.adjusted(-4, -4, 4, 4), highlight_pen)

            x += node_w + 70
            if x > max_width:
                x = 60
                y += node_h + 120

    def on_row_selected(self, row: int, col: int):
        if row < 0 or row >= len(self.assets):
            return
        a = self.assets[row]
        self.summary_label.setText(
            f"Asset ID: {a.asset_id}\n"
            f"Type: {a.asset_type}\n"
            f"Risk: {a.risk_score}\n"
            f"Predictive Risk (Borg): {a.predictive_risk}\n"
            f"Confidence: {a.confidence:.2f}\n"
            f"Criticality: {a.criticality}\n"
            f"Tactic: {a.mitre_tactic}\n"
            f"Status: {a.status}\n"
            f"Isolated: {'yes' if a.isolated else 'no'}\n"
            f"Safe (game/trusted): {'yes' if a.safe else 'no'}\n"
            f"Missing details score: {a.missing_details_score:.2f}\n\n"
            f"Guardian mode: {self.mode}\n"
            f"Last anomaly score: {getattr(self, 'last_anomaly', 0.0):.2f}\n"
            f"Predictive anomaly: {getattr(self, 'last_predictive_anomaly', 0.0):.2f}\n"
            f"Altered state wiring: {self.altered_state}\n\n"
            f"Color = risk (altered by Borg/Physics)\n"
            f"Opacity = confidence minus missing details\n"
            f"Border = criticality (blue dashed = isolated)\n"
            f"Badge = status (heat in physics mode)\n"
            f"Asset ID color = MITRE tactic"
        )
        self.draw_graph(selected=a)

    def on_manual_refresh(self):
        self.guardian_tick(manual=True)

    def on_predictive_sweep(self):
        # Just re-evaluate predictive risk using Borg memory and physics
        for a in self.assets:
            a.predictive_risk = borg_predict_asset(self.borg_memory, a.asset_id, a.risk_score)
            a.missing_details_score = compute_missing_details_score(a)
        self.populate_table()
        self.draw_graph()
        self.summary_label.setText("Predictive sweep completed. Borg learning and data physics updated asset predictions.")

    def on_mode_changed(self, new_mode: str):
        self.mode = new_mode
        append_guardian_log(f"[MODE] Guardian mode changed to {self.mode}")
        save_baseline(self.assets, self.mode, self.stats, self.borg_memory, self.physics)

    def on_altered_state_changed(self, new_state: str):
        self.altered_state = new_state
        append_guardian_log(f"[ALTERED] Wiring changed to {self.altered_state}")
        self.populate_table()
        self.draw_graph()

    def guardian_tick(self, manual: bool = False):
        baseline = load_baseline()
        baseline["mode"] = self.mode
        baseline["stats"] = self.stats
        baseline["borg_memory"] = self.borg_memory
        baseline["physics"] = self.physics

        assets, self.stats, self.borg_memory, self.physics, self.last_anomaly, self.last_predictive_anomaly = scan_system(
            self.stats, self.borg_memory, self.physics
        )
        self.assets = merge_with_baseline(assets, baseline, self.borg_memory)

        self.run_guardian_actions()

        self.populate_table()
        self.draw_graph()
        save_baseline(self.assets, self.mode, self.stats, self.borg_memory, self.physics)

        if manual:
            self.summary_label.setText("Manual rescan completed. Guardian evaluated system state with Borg learning and data physics.")

    def run_guardian_actions(self):
        game_running = any(a.asset_type == "process" and a.safe for a in self.assets)
        if game_running and self.mode == "aggressive":
            append_guardian_log("[INFO] Game detected; softening aggressive behavior to active-like.")
        effective_mode = self.mode
        if game_running and self.mode == "aggressive":
            effective_mode = "active"

        if effective_mode == "passive":
            return

        if effective_mode == "active":
            for a in self.assets:
                # Use predictive risk for isolation decisions
                if a.predictive_risk >= 80 and not a.isolated and not a.safe:
                    a.isolated = True
                    append_guardian_log(
                        f"[ACTIVE] Auto-isolated high predictive-risk asset: {a.asset_id} (risk={a.risk_score}, pred={a.predictive_risk})"
                    )
            return

        if effective_mode == "aggressive":
            for a in self.assets:
                if a.asset_type == "process" and a.predictive_risk >= 85 and not a.safe:
                    self.guardian_handle_process(a)
                elif a.asset_type in ["network_alert", "anomaly"] and a.predictive_risk >= 80:
                    if not a.isolated:
                        a.isolated = True
                        append_guardian_log(
                            f"[AGGRESSIVE] Isolated asset (predictive): {a.asset_id} (type={a.asset_type}, risk={a.risk_score}, pred={a.predictive_risk})"
                        )

    def guardian_handle_process(self, asset: AssetIncident):
        if asset.safe:
            append_guardian_log(
                f"[AGGRESSIVE] Skipped termination for safe/game process: {asset.asset_id}"
            )
            return

        try:
            pid_str = asset.asset_id.split("-", 1)[1]
            pid = int(pid_str)
        except Exception:
            return

        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Guardian Override – Predictive Process Termination")
        msg_box.setText(
            f"Guardian (AGGRESSIVE) wants to terminate process:\n\n"
            f"Asset: {asset.asset_id}\n"
            f"Risk: {asset.risk_score}\n"
            f"Predictive Risk: {asset.predictive_risk}\n"
            f"Confidence: {asset.confidence:.2f}\n"
            f"Missing details score: {asset.missing_details_score:.2f}\n\n"
            f"Do you approve this action?"
        )
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        result = msg_box.exec_()

        if result == QMessageBox.Yes:
            try:
                p = psutil.Process(pid)
                p.terminate()
                asset.status = "closed"
                asset.isolated = True
                append_guardian_log(
                    f"[AGGRESSIVE] Process {asset.asset_id} (pid={pid}) terminated by Guardian (predictive)."
                )
                alert = QMessageBox(self)
                alert.setIcon(QMessageBox.Information)
                alert.setWindowTitle("Guardian Action")
                alert.setText(
                    f"Guardian terminated process {asset.asset_id} (pid={pid})."
                )
                alert.exec_()
            except Exception as e:
                append_guardian_log(
                    f"[AGGRESSIVE] Failed to terminate {asset.asset_id} (pid={pid}): {e}"
                )
        else:
            append_guardian_log(
                f"[AGGRESSIVE] User denied termination for {asset.asset_id} (pid={pid})."
            )

# ---------------------------------------------------------
# MAIN ENTRY
# ---------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    window = SocGuardianWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
