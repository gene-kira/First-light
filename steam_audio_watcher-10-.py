import time
import json
import os
import threading
import socket
import hashlib

import pythoncom
import psutil
import requests

import tkinter as tk
from tkinter import messagebox, ttk

from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume

from flask import Flask, request, jsonify

# -------------------------
# Global config / defaults
# -------------------------

CONFIG_FILE = "steam_borg_watcher_config.json"
LOG_FILE = "steam_borg_watcher_log.txt"

DEFAULT_CONFIG = {
    "mode": "aggressive",              # "aggressive" or "monitor"
    "auto_kill_timeout": 5,           # seconds
    "steam_exe_names": ["steam.exe", "steamwebhelper.exe"],
    "safe_game_exes": [
        "cs2.exe",
        "dota2.exe",
        "pubg.exe",
        "eldenring.exe",
        "rdr2.exe",
        "gtav.exe",
        "halo.exe",
        "doom.exe",
        "back4blood.exe",
        "toxiccommando.exe",
    ],
    "remote_play_processes": [
        "steamwebhelper.exe",
        "streaming_client.exe",
        "remoteplay.exe",
    ],
    "voice_processes": [
        "steamvoice.exe",
        "steam.exe",
        "steamwebhelper.exe",
        "chrome.exe",
        "google chrome for testing.exe",
        "pdpro7 hook.exe",
    ],
    "borg_sync_interval": 60,         # seconds
    "worker_id": socket.gethostname()
}

config_lock = threading.Lock()
config = {}

# -------------------------
# Logging
# -------------------------

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)

# -------------------------
# Config helpers
# -------------------------

def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = DEFAULT_CONFIG.copy()
            cfg.update(data)
            config = cfg
            log("Config loaded")
            return
        except Exception as e:
            log(f"Failed to load config, using defaults: {e}")
    config = DEFAULT_CONFIG.copy()
    save_config()

def save_config():
    with config_lock:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            log("Config saved")
        except Exception as e:
            log(f"Failed to save config: {e}")

def get_mode():
    with config_lock:
        return config.get("mode", "aggressive")

def set_mode(mode):
    with config_lock:
        if mode in ("aggressive", "monitor"):
            config["mode"] = mode
            save_config()
            log(f"Mode set to {mode}")

def get_auto_kill_timeout():
    with config_lock:
        return int(config.get("auto_kill_timeout", 5))

def set_auto_kill_timeout(val):
    with config_lock:
        config["auto_kill_timeout"] = val
        save_config()
        log(f"Auto-kill timeout set to {val}")

def get_steam_exe_names():
    with config_lock:
        return [n.lower() for n in config.get("steam_exe_names", [])]

def get_safe_game_exes():
    with config_lock:
        return [n.lower() for n in config.get("safe_game_exes", [])]

def set_safe_game_exes(exes):
    with config_lock:
        config["safe_game_exes"] = exes
        save_config()
        log(f"Safe game EXEs updated: {exes}")

def add_safe_game_exe(exe_name):
    exe_name = exe_name.strip().lower()
    if not exe_name:
        return
    with config_lock:
        safe = config.get("safe_game_exes", [])
        if exe_name not in safe:
            safe.append(exe_name)
            config["safe_game_exes"] = safe
            save_config()
            log(f"Added safe game EXE: {exe_name}")

def get_remote_play_processes():
    with config_lock:
        return [n.lower() for n in config.get("remote_play_processes", [])]

def get_voice_processes():
    with config_lock:
        return [n.lower() for n in config.get("voice_processes", [])]

# -------------------------
# Identity badges
# -------------------------

def worker_color(worker_id):
    h = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    r = min(255, int(r * 1.5))
    g = min(255, int(g * 1.5))
    b = min(255, int(b * 1.5))
    return f"#{r:02x}{g:02x}{b:02x}"

def worker_icon(worker_id):
    lid = worker_id.lower()
    if "game" in lid or "rig" in lid:
        return "🎮"
    if "chat" in lid:
        return "💬"
    if "lap" in lid:
        return "💻"
    if "desk" in lid or "pc" in lid:
        return "🖥️"
    if "srv" in lid or "server" in lid:
        return "⚙️"
    return "🎮"

# -------------------------
# Borg Queen / Worker
# -------------------------

QUEEN_PORT = 5000
queen_app = Flask(__name__)

global_safe_exes = set()
global_voice_events = []  # list of {worker_id, game, voice_state, ts}
global_events = []        # list of {ts, worker_id, event}
workers = {}              # worker_id -> {"last_seen", "safe_exes", "color", "icon", "ghost_count"}
queen_ip = None
queen_candidates = []
is_queen = False
borg_ready = False
borg_network_blocked = False

@queen_app.route("/report_safe_exes", methods=["POST"])
def report_safe_exes():
    data = request.get_json(force=True)
    worker_id = data.get("worker_id", "unknown")
    safe_exes = data.get("safe_exes", [])
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    w = workers.get(worker_id, {"ghost_count": 0})
    w["last_seen"] = ts
    w["safe_exes"] = safe_exes
    workers[worker_id] = w

    global_safe_exes.update(x.lower() for x in safe_exes)

    return jsonify({
        "status": "ok",
        "merged_safe_exes": sorted(global_safe_exes)
    })

@queen_app.route("/global_safe_exes", methods=["GET"])
def get_global_safe_exes():
    return jsonify({
        "global_safe_exes": sorted(global_safe_exes)
    })

@queen_app.route("/report_voice_state", methods=["POST"])
def report_voice_state():
    data = request.get_json(force=True)
    worker_id = data.get("worker_id", "unknown")
    game = data.get("game", None)
    voice_state = data.get("voice_state", "idle")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    global_voice_events.append({
        "worker_id": worker_id,
        "game": game,
        "voice_state": voice_state,
        "ts": ts
    })

    states = [e["voice_state"] for e in global_voice_events[-50:]]
    if "legit" in states:
        global_state = "legit"
    else:
        suspicious_count = states.count("suspicious")
        if suspicious_count > 1:
            global_state = "ghost"
        elif suspicious_count == 1:
            global_state = "suspicious"
        else:
            global_state = "idle"

    if global_state == "ghost":
        w = workers.get(worker_id, {"ghost_count": 0})
        w["ghost_count"] = w.get("ghost_count", 0) + 1
        workers[worker_id] = w

    global_events.append({
        "ts": ts,
        "worker_id": worker_id,
        "event": f"voice_state={voice_state}, global={global_state}, game={game}"
    })

    return jsonify({
        "status": "ok",
        "global_voice_state": global_state
    })

@queen_app.route("/global_voice_state", methods=["GET"])
def get_global_voice_state():
    states = [e["voice_state"] for e in global_voice_events[-50:]]
    if "legit" in states:
        global_state = "legit"
    else:
        suspicious_count = states.count("suspicious")
        if suspicious_count > 1:
            global_state = "ghost"
        elif suspicious_count == 1:
            global_state = "suspicious"
        else:
            global_state = "idle"
    return jsonify({
        "global_voice_state": global_state
    })

@queen_app.route("/report_event", methods=["POST"])
def report_event():
    data = request.get_json(force=True)
    worker_id = data.get("worker_id", "unknown")
    event = data.get("event", "")
    ts = data.get("ts", time.strftime("%Y-%m-%d %H:%M:%S"))

    global_events.append({
        "ts": ts,
        "worker_id": worker_id,
        "event": event
    })

    return jsonify({"status": "ok"})

@queen_app.route("/global_events", methods=["GET"])
def get_global_events():
    return jsonify({
        "events": global_events[-200:]
    })

@queen_app.route("/report_identity", methods=["POST"])
def report_identity():
    data = request.get_json(force=True)
    worker_id = data.get("worker_id", "unknown")
    color = data.get("color", "#00ff00")
    icon = data.get("icon", "🎮")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    w = workers.get(worker_id, {"ghost_count": 0})
    w["last_seen"] = ts
    w["color"] = color
    w["icon"] = icon
    workers[worker_id] = w

    global_events.append({
        "ts": ts,
        "worker_id": worker_id,
        "event": f"identity_registered color={color} icon={icon}"
    })

    return jsonify({"status": "ok"})

@queen_app.route("/workers", methods=["GET"])
def get_workers():
    return jsonify({
        "workers": workers
    })

def build_queen_candidates():
    global queen_candidates
    candidates = []

    candidates.append("127.0.0.1")
    candidates.append("localhost")

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        candidates.append(host_ip)
    except Exception:
        pass

    try:
        host_name = socket.gethostname()
        for addr in socket.getaddrinfo(host_name, None):
            ip = addr[4][0]
            if ip not in candidates and ":" not in ip:
                candidates.append(ip)
    except Exception:
        pass

    queen_candidates = list(dict.fromkeys(candidates))
    log(f"[BORG] Queen IP candidates: {queen_candidates}")

def start_queen_server():
    def run():
        global borg_ready
        log("Borg Queen HTTP server starting")
        queen_app.run(host="0.0.0.0", port=QUEEN_PORT, debug=False, use_reloader=False)
        borg_ready = False
    t = threading.Thread(target=run, daemon=True)
    t.start()

def try_become_queen():
    global is_queen, queen_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", QUEEN_PORT))
        s.close()
        is_queen = True
        build_queen_candidates()
        queen_ip = queen_candidates[0] if queen_candidates else "127.0.0.1"
        log(f"[BORG] This node is Borg Queen (primary IP={queen_ip})")
        start_queen_server()
    except OSError:
        is_queen = False
        build_queen_candidates()
        queen_ip = queen_candidates[0] if queen_candidates else "127.0.0.1"
        log(f"[BORG] This node is Worker, Queen assumed at {queen_ip}")

# -------------------------
# Safe JSON helper
# -------------------------

def safe_json(resp):
    try:
        return resp.json()
    except Exception as e:
        log(f"safe_json: failed to parse JSON: {e}")
        return {}

# -------------------------
# Borg readiness + sync
# -------------------------

def borg_probe_once(ip):
    try:
        r = requests.get(f"http://{ip}:{QUEEN_PORT}/global_safe_exes", timeout=0.5)
        if r.status_code == 200:
            return True
    except Exception:
        return False
    return False

def borg_wait_for_queen():
    global queen_ip, borg_ready, borg_network_blocked
    borg_ready = False
    borg_network_blocked = False

    if not queen_candidates:
        build_queen_candidates()

    for ip in queen_candidates:
        if borg_probe_once(ip):
            queen_ip = ip
            borg_ready = True
            log(f"BORG: Queen is ready at {queen_ip}")
            return True

    for _ in range(20):
        for ip in queen_candidates:
            if borg_probe_once(ip):
                queen_ip = ip
                borg_ready = True
                log(f"BORG: Queen is ready at {queen_ip}")
                return True
        time.sleep(0.3)

    borg_ready = False
    borg_network_blocked = True
    log("BORG: Queen not reachable on any candidate IP (possible firewall / loopback block)")
    return False

def borg_report_safe_exes():
    global queen_ip
    if not queen_ip or not borg_ready:
        return
    with config_lock:
        worker_id = config.get("worker_id", socket.gethostname())
        safe = config.get("safe_game_exes", [])
    try:
        resp = requests.post(
            f"http://{queen_ip}:{QUEEN_PORT}/report_safe_exes",
            json={"worker_id": worker_id, "safe_exes": safe},
            timeout=3,
        )
        data = safe_json(resp)
        merged = data.get("merged_safe_exes", [])
        if merged:
            with config_lock:
                config["safe_game_exes"] = merged
                save_config()
        log(f"Borg sync: reported safe EXEs, merged={merged}")
    except Exception as e:
        log(f"Borg report failed: {e}")

def borg_pull_global_safe_exes():
    global queen_ip
    if not queen_ip or not borg_ready:
        return
    try:
        resp = requests.get(f"http://{queen_ip}:{QUEEN_PORT}/global_safe_exes", timeout=3)
        data = safe_json(resp)
        global_safe = data.get("global_safe_exes", [])
        if global_safe:
            with config_lock:
                config["safe_game_exes"] = global_safe
                save_config()
        log(f"Borg pull: global safe EXEs={global_safe}")
    except Exception as e:
        log(f"Borg pull failed: {e}")

def borg_report_voice_state(worker_id, game, voice_state):
    global queen_ip
    if not queen_ip or not borg_ready:
        return None
    try:
        resp = requests.post(
            f"http://{queen_ip}:{QUEEN_PORT}/report_voice_state",
            json={"worker_id": worker_id, "game": game, "voice_state": voice_state},
            timeout=3,
        )
        data = safe_json(resp)
        return data.get("global_voice_state", "idle")
    except Exception as e:
        log(f"Borg voice report failed: {e}")
        return None

def borg_pull_global_voice_state():
    global queen_ip
    if not queen_ip or not borg_ready:
        return "idle"
    try:
        resp = requests.get(f"http://{queen_ip}:{QUEEN_PORT}/global_voice_state", timeout=3)
        data = safe_json(resp)
        return data.get("global_voice_state", "idle")
    except Exception as e:
        log(f"Borg voice pull failed: {e}")
        return "idle"

def borg_push_event(worker_id, event):
    global queen_ip
    if not queen_ip or not borg_ready:
        return
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        requests.post(
            f"http://{queen_ip}:{QUEEN_PORT}/report_event",
            json={"worker_id": worker_id, "event": event, "ts": ts},
            timeout=3,
        )
    except Exception as e:
        log(f"Borg event push failed: {e}")

def borg_push_identity(worker_id, color, icon):
    global queen_ip
    if not queen_ip or not borg_ready:
        return
    try:
        requests.post(
            f"http://{queen_ip}:{QUEEN_PORT}/report_identity",
            json={"worker_id": worker_id, "color": color, "icon": icon},
            timeout=3,
        )
    except Exception as e:
        log(f"Borg identity push failed: {e}")

def borg_sync_loop():
    while True:
        borg_wait_for_queen()
        if borg_ready:
            borg_report_safe_exes()
            borg_pull_global_safe_exes()
        with config_lock:
            interval = config.get("borg_sync_interval", 60)
        time.sleep(interval)

# -------------------------
# Detection helpers
# -------------------------

def detect_running_game():
    safe_games = set(get_safe_game_exes())
    for proc in psutil.process_iter(["name"]):
        name = proc.info["name"]
        if not name:
            continue
        lname = name.lower()
        if lname in safe_games:
            return lname
    return None

def is_steam_downloading():
    for proc in psutil.process_iter(["name", "cmdline"]):
        name = proc.info["name"]
        if not name:
            continue
        if name.lower() == "steam.exe":
            cmd = " ".join(proc.info.get("cmdline", []))
            if "download" in cmd.lower() or "update" in cmd.lower():
                return True
    return False

def is_remote_play_active():
    rp_names = set(get_remote_play_processes())
    for proc in psutil.process_iter(["name"]):
        name = proc.info["name"]
        if not name:
            continue
        if name.lower() in rp_names:
            return True
    return False

def is_voice_active():
    voice_names = set(get_voice_processes())
    for proc in psutil.process_iter(["name"]):
        name = proc.info["name"]
        if not name:
            continue
        if name.lower() in voice_names:
            return True
    return False

def auto_learn_safe_games():
    safe_games = set(get_safe_game_exes())
    steam_names = set(get_steam_exe_names())

    try:
        sessions = AudioUtilities.GetAllSessions()
    except Exception:
        return

    for session in sessions:
        try:
            proc = session.Process
            if not proc:
                continue
            name = proc.name()
            if not name:
                continue
            lname = name.lower()
            if lname in steam_names:
                continue
            if lname in safe_games:
                continue

            volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
            vol = volume_obj.GetMasterVolume()
            muted = volume_obj.GetMute()
            if vol > 0.01 and not muted:
                add_safe_game_exe(lname)
                log(f"Auto-learned safe game EXE: {lname}")
        except Exception:
            continue

# -------------------------
# Audio control
# -------------------------

def mute_session(volume_obj):
    try:
        volume_obj.SetMute(True, None)
    except Exception as e:
        log(f"Failed to mute session: {e}")

def kill_steam_voice_only():
    voice_names = set(get_voice_processes())
    for proc in psutil.process_iter(["name", "pid"]):
        name = proc.info["name"]
        if not name:
            continue
        lname = name.lower()
        if lname in voice_names or "steamwebhelper.exe" in lname:
            try:
                psutil.Process(proc.info["pid"]).terminate()
                log(f"KILLED voice-related process: {name} PID={proc.info['pid']}")
            except Exception as e:
                log(f"Kill failed for {name}: {e}")

# -------------------------
# Popup
# -------------------------

def popup_warning():
    def _show():
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning(
            "Steam / Voice Audio Leak Detected",
            "Voice/chat audio is outputting while idle.\n"
            "If this continues for the configured timeout, voice-related processes may be auto-killed."
        )
        root.destroy()
    t = threading.Thread(target=_show, daemon=True)
    t.start()

# -------------------------
# Voice indicator (global)
# -------------------------

class SteamVoiceIndicator:
    def __init__(self, canvas):
        self.canvas = canvas
        self.level = 0
        self.running = True
        self.last_talker = "none"
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()

    def loop(self):
        while self.running:
            try:
                sessions = AudioUtilities.GetAllSessions()
                active = False
                level = 0
                talker = "none"

                safe_games = set(get_safe_game_exes())
                voice_names = set(get_voice_processes())
                steam_names = set(get_steam_exe_names())

                for session in sessions:
                    proc = session.Process
                    if not proc:
                        continue
                    name = proc.name()
                    if not name:
                        continue
                    lname = name.lower()

                    vol_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                    vol = vol_obj.GetMasterVolume()
                    muted = vol_obj.GetMute()

                    if vol <= 0.01 or muted:
                        continue

                    if lname in safe_games:
                        continue

                    if lname in voice_names or lname in steam_names or "chrome" in lname or "google chrome for testing" in lname or "pdpro7" in lname:
                        active = True
                        lvl = int(vol * 100)
                        if lvl > level:
                            level = lvl
                            talker = name

                self.level = level if active else 0
                self.last_talker = talker
                self.draw()
            except Exception:
                pass

            time.sleep(0.1)

    def draw(self):
        try:
            self.canvas.delete("all")
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()

            bar_width = int((self.level / 100) * w)
            if self.level == 0:
                color = "#222222"
            elif self.level < 30:
                color = "#00ff00"
            elif self.level < 60:
                color = "#ffff00"
            else:
                color = "#ff0000"

            self.canvas.create_rectangle(0, 0, bar_width, h, fill=color, outline="")
            text = f"Voice Level: {self.level}% | Talker: {self.last_talker}"
            self.canvas.create_text(
                w // 2,
                h // 2,
                text=text,
                fill="#ffffff",
                font=("Consolas", 10),
            )
        except Exception:
            pass

# -------------------------
# Watcher loop
# -------------------------

def watcher_loop():
    pythoncom.CoInitialize()
    log("Watcher loop started")

    while True:
        auto_learn_safe_games()

        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception as e:
            log(f"Failed to get audio sessions: {e}")
            time.sleep(2)
            continue

        steam_sessions = []
        steam_names = set(get_steam_exe_names())
        voice_names = set(get_voice_processes())
        safe_games = set(get_safe_game_exes())

        for session in sessions:
            try:
                proc = session.Process
                if not proc:
                    continue
                name = proc.name()
                if not name:
                    continue
                lname = name.lower()

                if lname in steam_names or lname in voice_names or "chrome" in lname or "google chrome for testing" in lname or "pdpro7" in lname:
                    steam_sessions.append(session)
            except Exception:
                continue

        if not steam_sessions:
            time.sleep(1)
            continue

        current_game = detect_running_game()
        voice_active = is_voice_active()
        remote_play_active = is_remote_play_active()

        if voice_active and current_game is not None:
            voice_state = "legit"
        elif voice_active and current_game is None:
            voice_state = "suspicious"
        else:
            voice_state = "idle"

        with config_lock:
            worker_id = config.get("worker_id", socket.gethostname())

        global_voice_state = borg_report_voice_state(worker_id, current_game, voice_state)
        if global_voice_state is None:
            global_voice_state = borg_pull_global_voice_state()

        for session in steam_sessions:
            try:
                volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                vol = volume_obj.GetMasterVolume()
                muted = volume_obj.GetMute()
                pid = session.Process.pid
                name = session.Process.name()
                lname = name.lower()

                if vol <= 0.01 or muted:
                    continue

                if current_game is not None and lname in safe_games:
                    log(f"Audio OK (safe game running: {current_game}, process={name})")
                    continue

                if is_steam_downloading() and "steam.exe" in lname:
                    log("Steam audio OK (downloading/updating)")
                    continue

                if remote_play_active and ("remoteplay" in lname or "streaming_client" in lname):
                    log("Audio OK (Remote Play active)")
                    continue

                if voice_active and global_voice_state == "legit":
                    log("Voice OK (global legit voice state)")
                    continue

                mode = get_mode()
                timeout = get_auto_kill_timeout()
                log(f"Voice/Chat audio leak detected: {name} PID={pid}, mode={mode}, global_voice_state={global_voice_state}")
                borg_push_event(worker_id, f"audio_leak pid={pid} name={name} global_voice_state={global_voice_state}")

                mute_session(volume_obj)
                log("Voice/Chat auto-muted due to leak")
                popup_warning()

                if mode == "monitor":
                    log("Monitor-only mode: no auto-kill, just logging and warning")
                    continue

                time.sleep(timeout)

                try:
                    volume_obj2 = session._ctl.QueryInterface(ISimpleAudioVolume)
                    vol2 = volume_obj2.GetMasterVolume()
                    muted2 = volume_obj2.GetMute()
                except Exception as e:
                    log(f"Re-check failed: {e}")
                    continue

                if vol2 > 0.01 and not muted2:
                    if global_voice_state in ("suspicious", "ghost"):
                        log(f"Voice/Chat still leaking audio after timeout (global_voice_state={global_voice_state}) → AUTO-KILL voice-related processes")
                        borg_push_event(worker_id, "auto_kill voice-related processes")
                        kill_steam_voice_only()
                    else:
                        log("Voice/Chat still leaking audio but global voice state not suspicious → no kill")
                else:
                    log("Voice/Chat stopped leaking audio after timeout → no kill")

            except Exception as e:
                log(f"Error in watcher loop: {e}")

        time.sleep(1)

# -------------------------
# GUI
# -------------------------

class SteamWatcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steam Borg Watcher v12.7")
        self.root.geometry("780x700")

        self.mode_var = tk.StringVar(value=get_mode())
        self.safe_games_var = tk.StringVar(value=", ".join(get_safe_game_exes()))

        self._build_ui()
        self._start_refresh_thread()
        self._start_history_thread()
        self._start_heatmap_thread()

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        mode_label = ttk.Label(frame, text="Mode:")
        mode_label.grid(row=0, column=0, sticky="w")

        self.mode_combo = ttk.Combobox(
            frame,
            textvariable=self.mode_var,
            values=["aggressive", "monitor"],
            state="readonly",
            width=15
        )
        self.mode_combo.grid(row=0, column=1, sticky="w", padx=5)

        apply_mode_btn = ttk.Button(frame, text="Apply Mode", command=self.apply_mode)
        apply_mode_btn.grid(row=0, column=2, sticky="w", padx=5)

        timeout_label = ttk.Label(frame, text="Auto-kill timeout (seconds):")
        timeout_label.grid(row=1, column=0, sticky="w")

        self.timeout_entry = ttk.Entry(frame, width=10)
        self.timeout_entry.insert(0, str(get_auto_kill_timeout()))
        self.timeout_entry.grid(row=1, column=1, sticky="w", padx=5)

        timeout_btn = ttk.Button(frame, text="Apply Timeout", command=self.apply_timeout)
        timeout_btn.grid(row=1, column=2, sticky="w", padx=5)

        sg_label = ttk.Label(frame, text="Safe game EXEs (comma-separated):")
        sg_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

        self.sg_entry = ttk.Entry(frame, textvariable=self.safe_games_var, width=60)
        self.sg_entry.grid(row=3, column=0, columnspan=3, sticky="we", pady=5)

        sg_btn = ttk.Button(frame, text="Apply Safe Games", command=self.apply_safe_games)
        sg_btn.grid(row=4, column=0, sticky="w", pady=5)

        add_label = ttk.Label(frame, text="Add single safe EXE:")
        add_label.grid(row=5, column=0, sticky="w", pady=(10, 0))

        self.add_entry = ttk.Entry(frame, width=20)
        self.add_entry.grid(row=5, column=1, sticky="w", padx=5)

        add_btn = ttk.Button(frame, text="Add", command=self.add_single_safe_game)
        add_btn.grid(row=5, column=2, sticky="w", padx=5)

        self.status_label = ttk.Label(frame, text="Status: starting...", foreground="green")
        self.status_label.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))

        self.borg_label = ttk.Label(frame, text="BORG: initializing...", foreground="#ffaa00")
        self.borg_label.grid(row=7, column=0, columnspan=3, sticky="w", pady=(2, 0))

        self.network_label = ttk.Label(frame, text="Network: probing...", foreground="#cccccc")
        self.network_label.grid(row=8, column=0, columnspan=3, sticky="w", pady=(2, 8))

        history_label = ttk.Label(frame, text="Event History (Neon feed):")
        history_label.grid(row=9, column=0, sticky="w", pady=(10, 0))

        self.history_box = tk.Text(frame, height=8, width=80, state="disabled", bg="#101010", fg="#00ffcc")
        self.history_box.grid(row=10, column=0, columnspan=3, sticky="we")

        heatmap_label = ttk.Label(frame, text="Ghost-Audio Heatmap (Neon Grid):")
        heatmap_label.grid(row=11, column=0, sticky="w", pady=(10, 0))

        self.heatmap_canvas = tk.Canvas(frame, width=760, height=140, bg="#000000",
                                        highlightthickness=1, highlightbackground="#333333")
        self.heatmap_canvas.grid(row=12, column=0, columnspan=3, sticky="we")

        indicator_label = ttk.Label(frame, text="Global Voice Indicator:")
        indicator_label.grid(row=13, column=0, sticky="w", pady=(10, 0))

        self.voice_canvas = tk.Canvas(frame, width=760, height=40, bg="#000000",
                                      highlightthickness=1, highlightbackground="#333333")
        self.voice_canvas.grid(row=14, column=0, columnspan=3, sticky="we")

        self.voice_indicator = SteamVoiceIndicator(self.voice_canvas)

    # ---- threaded apply actions ----

    def apply_mode(self):
        threading.Thread(target=self._apply_mode_thread, daemon=True).start()

    def _apply_mode_thread(self):
        mode = self.mode_var.get()
        set_mode(mode)
        def update():
            self.status_label.config(text=f"Status: mode set to {mode}", foreground="blue")
        self.root.after(0, update)

    def apply_timeout(self):
        threading.Thread(target=self._apply_timeout_thread, daemon=True).start()

    def _apply_timeout_thread(self):
        val = self.timeout_entry.get().strip()
        try:
            t = int(val)
            if t <= 0:
                raise ValueError
            set_auto_kill_timeout(t)
            def update():
                self.status_label.config(text=f"Status: timeout set to {t}s", foreground="blue")
            self.root.after(0, update)
        except Exception:
            def show_err():
                messagebox.showerror("Invalid timeout", "Please enter a positive integer.")
            self.root.after(0, show_err)

    def apply_safe_games(self):
        threading.Thread(target=self._apply_safe_games_thread, daemon=True).start()

    def _apply_safe_games_thread(self):
        text = self.sg_entry.get()
        exes = [x.strip().lower() for x in text.split(",") if x.strip()]
        set_safe_game_exes(exes)
        def update():
            self.safe_games_var.set(", ".join(exes))
            self.status_label.config(text="Status: safe games updated", foreground="blue")
        self.root.after(0, update)

    def add_single_safe_game(self):
        threading.Thread(target=self._add_single_safe_game_thread, daemon=True).start()

    def _add_single_safe_game_thread(self):
        exe = self.add_entry.get().strip()
        if not exe:
            return
        add_safe_game_exe(exe)
        def update():
            self.add_entry.delete(0, tk.END)
            self.safe_games_var.set(", ".join(get_safe_game_exes()))
            self.status_label.config(text=f"Status: added safe EXE {exe}", foreground="blue")
        self.root.after(0, update)

    # ---- background refreshers ----

    def _refresh_status(self):
        while True:
            mode = get_mode()
            timeout = get_auto_kill_timeout()
            sg = ", ".join(get_safe_game_exes())
            role = "Queen" if is_queen else "Worker"
            global_voice_state = borg_pull_global_voice_state()
            borg_state = "ready" if borg_ready else "not ready"
            text = (
                f"Status: running | role={role} | mode={mode} | "
                f"timeout={timeout}s | global_voice_state={global_voice_state} | "
                f"safe_games={sg}"
            )
            borg_text = f"BORG: {borg_state}"
            borg_color = "#00ff66" if borg_ready else "#ffaa00"

            if borg_network_blocked:
                net_text = "Network: Borg Queen unreachable (check firewall / loopback)"
                net_color = "#ff4444"
            else:
                net_text = "Network: OK"
                net_color = "#00dd88"

            def update():
                self.status_label.config(text=text, foreground="#00ff66")
                self.borg_label.config(text=borg_text, foreground=borg_color)
                self.network_label.config(text=net_text, foreground=net_color)
            try:
                self.root.after(0, update)
            except Exception:
                break
            time.sleep(5)

    def _refresh_history(self):
        while True:
            try:
                if not queen_ip or not borg_ready:
                    time.sleep(3)
                    continue
                resp = requests.get(f"http://{queen_ip}:{QUEEN_PORT}/global_events", timeout=3)
                data = safe_json(resp)
                events = data.get("events", [])
                lines = []
                for e in events:
                    wid = e.get("worker_id", "?")
                    icon = worker_icon(wid)
                    lines.append(f"[{e.get('ts','?')}] {icon} {wid}: {e.get('event','')}")
                text = "\n".join(lines)

                def update():
                    self.history_box.config(state="normal")
                    self.history_box.delete("1.0", tk.END)
                    self.history_box.insert(tk.END, text)
                    self.history_box.config(state="disabled")

                self.root.after(0, update)
            except Exception:
                pass
            time.sleep(5)

    def _refresh_heatmap(self):
        while True:
            try:
                if not queen_ip or not borg_ready:
                    time.sleep(3)
                    continue
                resp = requests.get(f"http://{queen_ip}:{QUEEN_PORT}/workers", timeout=3)
                data = safe_json(resp)
                workers_data = data.get("workers", {})
                def update():
                    self.heatmap_canvas.delete("all")
                    if not workers_data:
                        return
                    margin = 10
                    square_size = 70
                    spacing = 10
                    x = margin
                    y = margin
                    for wid, info in workers_data.items():
                        color = info.get("color", worker_color(wid))
                        icon = info.get("icon", worker_icon(wid))
                        ghost_count = info.get("ghost_count", 0)
                        intensity = min(255, ghost_count * 40)
                        base_color = color
                        try:
                            r = int(base_color[1:3], 16)
                            g = int(base_color[3:5], 16)
                            b = int(base_color[5:7], 16)
                        except Exception:
                            r, g, b = 0, 255, 255
                        r = min(255, r + intensity)
                        g = max(0, g - intensity // 2)
                        fill = f"#{r:02x}{g:02x}{b:02x}"

                        self.heatmap_canvas.create_rectangle(
                            x, y, x + square_size, y + square_size,
                            fill=fill, outline="#222222", width=2
                        )
                        self.heatmap_canvas.create_text(
                            x + square_size / 2, y + square_size / 2 - 12,
                            text=icon, fill="#ffffff", font=("Segoe UI Emoji", 18)
                        )
                        self.heatmap_canvas.create_text(
                            x + square_size / 2, y + square_size / 2 + 12,
                            text=f"{wid}\nghost={ghost_count}",
                            fill="#ffffff", font=("Consolas", 8)
                        )

                        x += square_size + spacing
                        if x + square_size + margin > 760:
                            x = margin
                            y += square_size + spacing
                self.root.after(0, update)
            except Exception:
                pass
            time.sleep(5)

    def _start_refresh_thread(self):
        t = threading.Thread(target=self._refresh_status, daemon=True)
        t.start()

    def _start_history_thread(self):
        t = threading.Thread(target=self._refresh_history, daemon=True)
        t.start()

    def _start_heatmap_thread(self):
        t = threading.Thread(target=self._refresh_heatmap, daemon=True)
        t.start()

# -------------------------
# Startup
# -------------------------

def start_watcher_thread():
    t = threading.Thread(target=watcher_loop, daemon=True)
    t.start()

def start_borg_sync_thread():
    t = threading.Thread(target=borg_sync_loop, daemon=True)
    t.start()

def borg_startup_thread():
    try_become_queen()
    borg_wait_for_queen()
    with config_lock:
        worker_id = config.get("worker_id", socket.gethostname())
    color = worker_color(worker_id)
    icon = worker_icon(worker_id)
    borg_push_identity(worker_id, color, icon)
    start_watcher_thread()
    start_borg_sync_thread()

def main():
    load_config()
    log("Steam Borg Watcher v12.7 starting")

    root = tk.Tk()
    gui = SteamWatcherGUI(root)

    t = threading.Thread(target=borg_startup_thread, daemon=True)
    t.start()

    root.mainloop()

if __name__ == "__main__":
    main()
