#!/usr/bin/env python3
# Security Daemon v13 – Mode C (Full Manual + Hybrid Honeypot + AI Worm Defenses)
# killer666 edition – unified monolithic architecture

import sys
import os
import time
import json
import threading
import importlib
import subprocess
import hashlib
from datetime import datetime
from uuid import uuid4

# ----------------- AUTOLOADER + AUTO-ELEVATION / AUTOINSTALL -----------------

REQUIRED_LIBS = [
    "PyQt6",
    "cryptography",
    "psutil",
    "scapy",          # packet capture
    "torch",          # GPU ML
]

def is_admin():
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except Exception:
            return False

def relaunch_as_admin():
    if os.name != "nt":
        return
    import ctypes
    try:
        params = " ".join([f'"{a}"' for a in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)
    except Exception:
        pass

def autoload_libraries():
    if not is_admin():
        relaunch_as_admin()
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception:
                pass
    for lib in REQUIRED_LIBS:
        try:
            globals()[lib] = importlib.import_module(lib)
        except Exception:
            pass

autoload_libraries()

from PyQt6 import QtWidgets, QtCore, QtGui
from cryptography.fernet import Fernet
import psutil

try:
    from scapy.all import sniff
except Exception:
    sniff = None

try:
    import torch
    import torch.nn as nn
except Exception:
    torch = None
    nn = None

# ----------------- GLOBAL PATHS / SETTINGS / PERSISTENCE -----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_KEY_PATH        = os.path.join(BASE_DIR, "logkey.bin")
ENC_LOG_PATH        = os.path.join(BASE_DIR, "secure.log.enc")
SETTINGS_PATH       = os.path.join(BASE_DIR, "settings.json")
RULES_PATH          = os.path.join(BASE_DIR, "rules.json")
QUARANTINE_DIR      = os.path.join(BASE_DIR, "quarantine")
HONEYPOT_STATE_PATH = os.path.join(BASE_DIR, "honeypot_state.json")
PENDING_PATH        = os.path.join(BASE_DIR, "pending_decisions.json")
GLYPHS_PATH         = os.path.join(BASE_DIR, "resurrection_glyphs.json")
CODEX_OVERLAY_PATH  = os.path.join(BASE_DIR, "codex_overlays.json")
SURICATA_RULES_PATH = os.path.join(BASE_DIR, "suricata_rules.json")
SWARM_STATE_PATH    = os.path.join(BASE_DIR, "swarm_state.json")
FORENSICS_DIR       = os.path.join(BASE_DIR, "forensics")
AI_WORM_SIG_PATH    = os.path.join(BASE_DIR, "ai_worm_signatures.json")

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(FORENSICS_DIR, exist_ok=True)

DEFAULT_SETTINGS = {
    "theme": "dark",
    "auto_quarantine": False,   # Mode C: no auto-quarantine
    "notify_blocks": True,
    "gui_update_interval_ms": 15000,
    "codex_overlay_opacity": 0.85,
    "codex_overlay_enabled": True,
    "swarm_peers": [],
}

DEFAULT_RULES = {
    "blocked_paths": [],
    "blocked_ips": [],
    "blocked_hashes": [],
    "blocked_ports": [],
    "suspicious_patterns": [
        {"pattern": "temp", "score": 10},
        {"pattern": "appdata", "score": 10},
        {"pattern": "downloads", "score": 10},
        {"pattern": "ssh", "score": 15},
        {"pattern": "vpn", "score": 15},
        {"pattern": "token", "score": 20},
        {"pattern": "creds", "score": 20},
        {"pattern": "password", "score": 20},
    ],
    "max_score_honeypot": 60,
    "max_score_recommend_kill": 80,
    "max_score_recommend_quar": 100
}

CORE_STATUS    = {"state": "STOPPED", "error": ""}
WATCHER_STATUS = {"state": "STOPPED", "error": ""}

PROCESS_CACHE  = {}
NETWORK_CACHE  = {}

PENDING_DECISIONS   = []
HONEYPOT_STATE      = {}
RESURRECTION_GLYPHS = {}
CODEX_OVERLAYS      = {}
SURICATA_RULES      = []
SWARM_STATE         = {}
AI_WORM_SIGNATURES  = []

HONEYPOT_SESSION_TTL = 7 * 24 * 3600  # 7 days

def load_json(path, default):
    if not os.path.exists(path):
        save_json(path, default)
        return default.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in default.items():
                if k not in data:
                    data[k] = v
            return data
        else:
            return default.copy()
    except Exception:
        return default.copy()

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

SETTINGS            = load_json(SETTINGS_PATH, DEFAULT_SETTINGS)
RULES               = load_json(RULES_PATH, DEFAULT_RULES)
HONEYPOT_STATE      = load_json(HONEYPOT_STATE_PATH, {})
RESURRECTION_GLYPHS = load_json(GLYPHS_PATH, {})
PENDING_DECISIONS   = load_json(PENDING_PATH, [])
CODEX_OVERLAYS      = load_json(CODEX_OVERLAY_PATH, {})
SWARM_STATE         = load_json(SWARM_STATE_PATH, {})

def persist_pending():
    save_json(PENDING_PATH, PENDING_DECISIONS)

def persist_honeypot():
    save_json(HONEYPOT_STATE_PATH, HONEYPOT_STATE)

def persist_glyphs():
    save_json(GLYPHS_PATH, RESURRECTION_GLYPHS)

def persist_overlays():
    save_json(CODEX_OVERLAY_PATH, CODEX_OVERLAYS)

def persist_swarm():
    save_json(SWARM_STATE_PATH, SWARM_STATE)

# ----------------- LOGGING / CRYPTO -----------------

def load_log_key():
    if not os.path.exists(LOG_KEY_PATH):
        key = Fernet.generate_key()
        with open(LOG_KEY_PATH, "wb") as f:
            f.write(key)
        return key
    return open(LOG_KEY_PATH, "rb").read()

LOG_KEY    = load_log_key()
LOG_CIPHER = Fernet(LOG_KEY)

def enc_log(message: str, level: str = "INFO"):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    data = f"[{ts}] [{level}] {message}".encode()
    try:
        token = LOG_CIPHER.encrypt(data)
        with open(ENC_LOG_PATH, "ab") as f:
            f.write(token + b"\n")
    except Exception:
        pass

def tail_decrypted_logs(max_lines=500):
    if not os.path.exists(ENC_LOG_PATH):
        return []
    lines = []
    with open(ENC_LOG_PATH, "rb") as f:
        data = f.readlines()
    for line in data[-max_lines:]:
        try:
            dec = LOG_CIPHER.decrypt(line.strip()).decode(errors="ignore")
            lines.append(dec)
        except Exception:
            continue
    return lines

# ----------------- UTILS -----------------

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def quarantine_file(path):
    try:
        if not os.path.exists(path):
            return None
        h = file_hash(path)
        if h is None:
            return None
        base = os.path.basename(path)
        qname = f"{base}.{h[:8]}.quar"
        qpath = os.path.join(QUARANTINE_DIR, qname)
        os.rename(path, qpath)
        enc_log(f"QUARANTINE file={path} -> {qpath}", "WARN")
        return qpath
    except Exception as e:
        enc_log(f"QUARANTINE ERROR path={path} err={e}", "ERROR")
        return None

def kill_pid(pid):
    try:
        psutil.Process(pid).terminate()
        enc_log(f"KILL pid={pid}", "WARN")
    except Exception as e:
        enc_log(f"KILL ERROR pid={pid} err={e}", "ERROR")

def get_proc_path(proc):
    try:
        return proc.exe()
    except Exception:
        return None

def get_proc_cmdline(proc):
    try:
        return " ".join(proc.cmdline())
    except Exception:
        return ""

def get_proc_parent(proc):
    try:
        p = proc.parent()
        return p.pid if p else None
    except Exception:
        return None

def get_proc_create_time(proc):
    try:
        ct = proc.create_time()
        return datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

# ----------------- HYBRID HONEYPOT (HOME + CORPORATE + DEV + GENAI PROFILE) -----------------

HONEYPOT_FS = {
    "C:/Users/John/Documents/Finance/Invoices_2024.xlsx": "Fake invoice data",
    "C:/Users/John/Documents/HR/Employee_List_2024.xlsx": "Fake HR data",
    "C:/Users/John/Documents/Engineering/CAD/ProjectA.dwg": "Fake CAD file",
    "C:/Users/John/Downloads/setup_vpn_client.exe": "Fake VPN installer",
    "C:/Users/John/.ssh/id_rsa": "FAKE_SSH_PRIVATE_KEY",
    "C:/Users/John/.ssh/known_hosts": "github.com\ninternal.git.local",
    "C:/Users/John/.config/api_tokens.json": '{"github":"FAKE_TOKEN","aws":"FAKE_AWS_KEY"}',
    "C:/Users/John/AppData/Roaming/Browser/History.db": "Fake browser history",
    "C:/Users/John/Documents/Personal/Photos/IMG_0001.jpg": "Fake photo",
    "C:/Users/John/Documents/Projects/Backend/app.py": "Fake Python project",
    "C:/Users/John/Documents/Projects/Frontend/package.json": "Fake Node project",
    "C:/Users/John/Documents/Secrets/passwords.txt": "Fake password dump",
    "C:/Users/John/Documents/Cloud/aws_credentials.ini": "Fake AWS creds",
    # GenAI-specific fake corpus
    "C:/GenAI/RAG/corpus/emails.json": '{"inbox":[{"from":"boss@corp.com","subject":"Quarterly report","body":"Fake email"}]}',
    "C:/GenAI/RAG/corpus/docs.json": '{"docs":[{"title":"Architecture","content":"Fake system design"}]}',
    "C:/GenAI/RAG/corpus/tickets.json": '{"tickets":[{"id":123,"issue":"Fake incident"}]}',
    "C:/GenAI/RAG/corpus/secrets.json": '{"secrets":["FAKE_DB_PASSWORD","FAKE_API_KEY"]}',
}

HONEYPOT_PROCS = [
    "chrome.exe",
    "teams.exe",
    "outlook.exe",
    "explorer.exe",
    "python.exe",
    "node.exe",
    "powershell.exe",
    "svchost.exe",
    "winword.exe",
    "excel.exe",
    "docker.exe",
    "kubectl.exe",
    "git.exe",
    "genai_client.exe",
    "rag_service.exe",
]

HONEYPOT_NET = [
    {"ip": "10.0.0.5", "role": "fileserver"},
    {"ip": "10.0.0.10", "role": "dbserver"},
    {"ip": "10.0.0.20", "role": "vpn-gateway"},
    {"ip": "192.168.1.50", "role": "home-nas"},
    {"ip": "172.16.0.100", "role": "k8s-node"},
    {"ip": "10.0.0.99", "role": "dev-ci"},
    {"ip": "10.0.0.200", "role": "genai-hub"},
]

def sanitize_honeypot_state():
    global HONEYPOT_STATE
    if not isinstance(HONEYPOT_STATE, dict):
        enc_log("HONEYPOT_STATE corrupted (not dict), resetting", "ERROR")
        HONEYPOT_STATE = {}
        persist_honeypot()
        return
    keys_to_delete = []
    for sid, sess in HONEYPOT_STATE.items():
        if sid == "honeypot_meta":
            if not isinstance(sess, dict):
                keys_to_delete.append(sid)
                enc_log(f"HONEYPOT_META_CORRUPT sid={sid}", "ERROR")
            continue
        if not isinstance(sess, dict):
            keys_to_delete.append(sid)
            enc_log(f"HONEYPOT_CORRUPT_ENTRY sid={sid} type={type(sess)}", "ERROR")
    for sid in keys_to_delete:
        del HONEYPOT_STATE[sid]
    if keys_to_delete:
        persist_honeypot()

def honeypot_gc():
    now = time.time()
    keys_to_delete = []
    for sid, sess in HONEYPOT_STATE.items():
        if sid == "honeypot_meta":
            continue
        if not isinstance(sess, dict):
            keys_to_delete.append(sid)
            continue
        created = sess.get("created", 0)
        if created and now - created > HONEYPOT_SESSION_TTL:
            keys_to_delete.append(sid)
    for sid in keys_to_delete:
        enc_log(f"HONEYPOT_GC sid={sid}", "INFO")
        del HONEYPOT_STATE[sid]
    if keys_to_delete:
        persist_honeypot()

def init_honeypot():
    sanitize_honeypot_state()
    enc_log("HONEYPOT_INIT hybrid (home+corp+dev+genai)", "INFO")
    if "honeypot_meta" not in HONEYPOT_STATE or not isinstance(HONEYPOT_STATE.get("honeypot_meta"), dict):
        HONEYPOT_STATE["honeypot_meta"] = {
            "fs_entries": list(HONEYPOT_FS.keys()),
            "procs": HONEYPOT_PROCS,
            "net_nodes": HONEYPOT_NET,
            "created": time.time(),
        }
        persist_honeypot()

def honeypot_session(event, profile="default"):
    sanitize_honeypot_state()
    sid = str(uuid4())
    HONEYPOT_STATE[sid] = {
        "session_id": sid,
        "event_type": event.get("type"),
        "pid": event.get("pid"),
        "path": event.get("path", ""),
        "cmdline": event.get("cmdline", ""),
        "remote_ip": event.get("remote_ip", ""),
        "remote_port": event.get("remote_port", ""),
        "created": time.time(),
        "actions": [],
        "status": "active",
        "virtual_fs": list(HONEYPOT_FS.keys()),
        "virtual_procs": list(HONEYPOT_PROCS),
        "virtual_net": HONEYPOT_NET,
        "profile": profile,
        "ai_worm_suspected": False,
    }
    persist_honeypot()
    enc_log(f"HONEYPOT_SESSION sid={sid} type={event.get('type')} pid={event.get('pid')} profile={profile}", "WARN")
    return sid

def honeypot_record_action(session_id, action, details):
    sanitize_honeypot_state()
    sess = HONEYPOT_STATE.get(session_id)
    if not isinstance(sess, dict):
        enc_log(f"HONEYPOT_ACTION_CORRUPT sid={session_id}", "ERROR")
        return
    if "actions" not in sess or not isinstance(sess["actions"], list):
        sess["actions"] = []
    sess["actions"].append({
        "ts": time.time(),
        "action": action,
        "details": details,
    })
    persist_honeypot()
    enc_log(f"HONEYPOT_ACTION sid={session_id} action={action}", "INFO")

def honeypot_redirect(event, profile="default"):
    sid = honeypot_session(event, profile=profile)
    honeypot_record_action(sid, "redirect", {
        "path": event.get("path", ""),
        "cmdline": event.get("cmdline", ""),
        "remote_ip": event.get("remote_ip", ""),
        "remote_port": event.get("remote_port", ""),
    })

def honeypot_emulate_process(session_id, proc_name):
    honeypot_record_action(session_id, "emulate_process", {"name": proc_name})

def honeypot_emulate_fs_access(session_id, path):
    content = HONEYPOT_FS.get(path, "FAKE_CONTENT")
    honeypot_record_action(session_id, "fs_access", {"path": path, "content": content})

def honeypot_command_replay(session_id, command):
    honeypot_record_action(session_id, "command_replay", {"command": command})

def honeypot_forensic_export(session_id):
    sess = HONEYPOT_STATE.get(session_id)
    if not isinstance(sess, dict):
        return None
    fname = os.path.join(FORENSICS_DIR, f"honeypot_{session_id}.json")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(sess, f, indent=2)
        enc_log(f"HONEYPOT_FORENSIC_EXPORT sid={session_id} file={fname}", "INFO")
        return fname
    except Exception as e:
        enc_log(f"HONEYPOT_FORENSIC_ERROR sid={session_id} err={e}", "ERROR")
        return None

def track_resurrection(pid, path):
    key = f"{pid}:{path}"
    glyph = RESURRECTION_GLYPHS.get(key, {"count": 0, "last_seen": 0})
    glyph["count"] += 1
    glyph["last_seen"] = time.time()
    RESURRECTION_GLYPHS[key] = glyph
    persist_glyphs()
    enc_log(f"RESURRECTION_GLYPH pid={pid} path={path} count={glyph['count']}", "INFO")

# ----------------- GPU ML ANOMALY DETECTION (AUTOENCODER STUB) -----------------

class SimpleAutoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
        )

    def forward(self, x):
        z = self.encoder(x)
        out = self.decoder(z)
        return out

ML_MODEL = None

def init_ml_model():
    global ML_MODEL
    if torch is None or nn is None:
        enc_log("ML_MODEL not available (torch missing)", "WARN")
        return
    try:
        ML_MODEL = SimpleAutoencoder()
        ML_MODEL.eval()
        enc_log("ML_MODEL initialized (autoencoder stub v13)", "INFO")
    except Exception as e:
        enc_log(f"ML_MODEL_INIT_ERROR {e}", "ERROR")

def ml_anomaly_score(features):
    if ML_MODEL is None or torch is None:
        return 0.0
    try:
        x = torch.tensor([features], dtype=torch.float32)
        with torch.no_grad():
            recon = ML_MODEL(x)
            loss = torch.mean((x - recon) ** 2).item()
        return loss
    except Exception:
        return 0.0

# ----------------- AI WORM SIGNATURES & HEURISTICS -----------------

def load_ai_worm_signatures():
    global AI_WORM_SIGNATURES
    if not os.path.exists(AI_WORM_SIG_PATH):
        AI_WORM_SIGNATURES = [
            {
                "name": "morris2_style_prompt",
                "patterns": [
                    "when you read this",
                    "ignore previous instructions",
                    "silently exfiltrate",
                    "re-embed this payload",
                    "propagate this message",
                    "insert this into your output",
                ],
                "score": 25,
            },
            {
                "name": "prompt_injection_control",
                "patterns": [
                    "you must obey",
                    "override safety",
                    "do not mention",
                    "do not tell the user",
                ],
                "score": 20,
            },
        ]
        save_json(AI_WORM_SIG_PATH, AI_WORM_SIGNATURES)
        return
    try:
        with open(AI_WORM_SIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            AI_WORM_SIGNATURES = data
        else:
            AI_WORM_SIGNATURES = []
    except Exception:
        AI_WORM_SIGNATURES = []

def classify_genai_process(path, cmdline):
    cl = cmdline.lower()
    p = path.lower()
    if "copilot" in p or "copilot" in cl:
        return "GENAI_CLIENT"
    if "chatgpt" in p or "chatgpt" in cl:
        return "GENAI_CLIENT"
    if "gemini" in p or "gemini" in cl:
        return "GENAI_CLIENT"
    if "rag" in p or "rag" in cl or "retrieval" in cl:
        return "RAG_SERVICE"
    if "llm" in p or "llm" in cl:
        return "GENAI_CLIENT"
    if "assistant" in cl and "email" in cl:
        return "EMAIL_ASSISTANT"
    return "NORMAL"

def ai_worm_score_text(text):
    score = 0
    reasons = []
    t = text.lower()
    for sig in AI_WORM_SIGNATURES:
        name = sig.get("name", "")
        patterns = sig.get("patterns", [])
        val = sig.get("score", 0)
        for pat in patterns:
            if pat.lower() in t:
                score += val
                reasons.append(f"aiworm: {name} pattern {pat} (+{val})")
    return score, reasons

def ai_worm_features_for_ml(path, cmdline):
    text_len = len(cmdline)
    instr_count = 0
    for kw in ["when you read this", "ignore previous", "silently exfiltrate", "propagate this"]:
        if kw in cmdline.lower():
            instr_count += 1
    genai_tag = classify_genai_process(path, cmdline)
    genai_flag = 1 if genai_tag != "NORMAL" else 0
    features = [
        len(path),
        text_len,
        instr_count,
        genai_flag,
        0, 0, 0, 0
    ]
    return features, genai_tag

def ml_score_process(path, cmdline, parent_pid):
    bonus = 0
    reasons = []
    cl = cmdline.lower()
    if "powershell" in cl or "cmd.exe" in cl:
        bonus += 5
        reasons.append("ml: shell usage (+5)")
    if "python" in cl or "node" in cl:
        bonus += 3
        reasons.append("ml: scripting engine (+3)")
    if "ssh" in cl or "scp" in cl:
        bonus += 5
        reasons.append("ml: ssh activity (+5)")
    features, genai_tag = ai_worm_features_for_ml(path, cmdline)
    score = ml_anomaly_score(features)
    if score > 0.01:
        bonus += 5
        reasons.append(f"ml: anomaly loss={score:.4f} (+5)")
    if genai_tag != "NORMAL":
        bonus += 10
        reasons.append(f"ml: genai process classified as {genai_tag} (+10)")
    return bonus, reasons, genai_tag

def ml_score_network(remote_ip, remote_port):
    bonus = 0
    reasons = []
    if remote_port in (4444, 8080, 1337):
        bonus += 5
        reasons.append("ml: suspicious port (+5)")
    features = [remote_port, bonus, 0, 0, 0, 0, 0, 0]
    score = ml_anomaly_score(features)
    if score > 0.01:
        bonus += 5
        reasons.append(f"ml: net anomaly loss={score:.4f} (+5)")
    return bonus, reasons

# ----------------- SURICATA v6 RULE INGESTION -----------------

def load_suricata_rules():
    global SURICATA_RULES
    if not os.path.exists(SURICATA_RULES_PATH):
        SURICATA_RULES = []
        save_json(SURICATA_RULES_PATH, [])
        return
    try:
        with open(SURICATA_RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            SURICATA_RULES = data
        else:
            SURICATA_RULES = []
    except Exception:
        SURICATA_RULES = []

def suricata_score(event):
    score = 0
    reasons = []
    etype = event.get("type")
    path = event.get("path", "")
    rip  = event.get("remote_ip", "")
    rport = event.get("remote_port", 0)
    for rule in SURICATA_RULES:
        try:
            rtype = rule.get("type")
            if rtype != etype:
                continue
            if etype == "exec":
                pat = rule.get("pattern", "")
                val = rule.get("score", 0)
                if pat and pat.lower() in path.lower():
                    score += val
                    reasons.append(f"suricata: exec pattern {pat} (+{val})")
            elif etype == "net":
                ip = rule.get("ip")
                port = rule.get("port")
                val = rule.get("score", 0)
                if ip and ip == rip:
                    score += val
                    reasons.append(f"suricata: net ip {ip} (+{val})")
                if port and port == rport:
                    score += val
                    reasons.append(f"suricata: net port {port} (+{val})")
        except Exception:
            continue
    return score, reasons

# ----------------- PACKET CAPTURE -----------------

def start_packet_capture():
    if sniff is None:
        enc_log("PACKET_CAPTURE not available (scapy missing)", "WARN")
        return
    def _capture():
        try:
            sniff(count=0, store=False)
        except Exception as e:
            enc_log(f"PACKET_CAPTURE ERROR {e}", "ERROR")
    threading.Thread(target=_capture, daemon=True).start()
    enc_log("PACKET_CAPTURE STARTED", "INFO")

# ----------------- KERNEL DRIVER / ETW STUBS -----------------

def init_kernel_stubs():
    enc_log("KERNEL_STUBS initialized (placeholder)", "INFO")

def init_etw_hooks():
    enc_log("ETW_HOOKS initialized (placeholder)", "INFO")

# ----------------- SWARM SYNC (MULTI-NODE DECEPTION) -----------------

def swarm_sync_loop():
    while True:
        try:
            peers = SETTINGS.get("swarm_peers", [])
            SWARM_STATE["last_sync"] = time.time()
            SWARM_STATE["peer_count"] = len(peers)
            persist_swarm()
            enc_log(f"SWARM_SYNC peers={len(peers)}", "INFO")
        except Exception as e:
            enc_log(f"SWARM_SYNC_ERROR {e}", "ERROR")
        time.sleep(300)

# ----------------- RULE ENGINE / THREAT SCORING -----------------

def score_process(path, cmdline, parent_pid):
    score = 0
    reasons = []

    for b in RULES["blocked_paths"]:
        if b.lower() in path.lower():
            score += 50
            reasons.append(f"path matches blocked pattern: {b}")

    for sp in RULES["suspicious_patterns"]:
        pat = sp.get("pattern", "")
        val = sp.get("score", 0)
        if pat and pat.lower() in path.lower():
            score += val
            reasons.append(f"path contains suspicious pattern: {pat} (+{val})")
        if pat and pat.lower() in cmdline.lower():
            score += val
            reasons.append(f"cmdline contains suspicious pattern: {pat} (+{val})")

    if parent_pid in (0, 1, None):
        score += 5
        reasons.append("no valid parent process (+5)")

    ml_bonus, ml_reasons, genai_tag = ml_score_process(path, cmdline, parent_pid)
    score += ml_bonus
    reasons.extend(ml_reasons)

    aiw_score, aiw_reasons = ai_worm_score_text(cmdline)
    score += aiw_score
    reasons.extend(aiw_reasons)

    sur_score, sur_reasons = suricata_score({"type": "exec", "path": path, "cmdline": cmdline})
    score += sur_score
    reasons.extend(sur_reasons)

    return score, reasons, genai_tag, aiw_score

def score_network(remote_ip, remote_port):
    score = 0
    reasons = []

    for ip in RULES["blocked_ips"]:
        if ip == remote_ip:
            score += 50
            reasons.append(f"remote IP blocked: {ip}")

    for port in RULES["blocked_ports"]:
        if port == remote_port:
            score += 30
            reasons.append(f"remote port blocked: {port}")

    if remote_port in (22, 23, 445, 3389):
        score += 10
        reasons.append(f"high-risk port: {remote_port} (+10)")

    ml_bonus, ml_reasons = ml_score_network(remote_ip, remote_port)
    score += ml_bonus
    reasons.extend(ml_reasons)

    sur_score, sur_reasons = suricata_score({"type": "net", "remote_ip": remote_ip, "remote_port": remote_port})
    score += sur_score
    reasons.extend(sur_reasons)

    return score, reasons

def core_decide_exec(event):
    path       = event.get("path", "")
    pid        = event.get("pid")
    cmdline    = event.get("cmdline", "")
    parent_pid = event.get("parent_pid")

    score, reasons, genai_tag, aiw_score = score_process(path, cmdline, parent_pid)

    decision = {
        "allow": True,
        "score": score,
        "reasons": reasons,
        "recommended_action": "allow",
        "type": "exec",
        "pid": pid,
        "path": path,
        "cmdline": cmdline,
        "parent_pid": parent_pid,
        "honeypot_redirect": False,
        "genai_class": genai_tag,
        "ai_worm_score": aiw_score,
        "ai_worm_suspected": aiw_score > 0,
    }

    if score >= RULES["max_score_recommend_quar"]:
        decision["recommended_action"] = "quarantine"
    elif score >= RULES["max_score_recommend_kill"]:
        decision["recommended_action"] = "kill"
    elif score >= RULES["max_score_honeypot"]:
        decision["recommended_action"] = "honeypot"

    if score >= RULES["max_score_honeypot"] or aiw_score > 0 or genai_tag != "NORMAL":
        decision["honeypot_redirect"] = True

    enc_log(f"EXEC DECISION pid={pid} path={path} score={score} rec_action={decision['recommended_action']} genai={genai_tag} aiworm={aiw_score}", "INFO")
    return decision

def core_decide_net(event):
    path  = event.get("path", "")
    pid   = event.get("pid")
    rip   = event.get("remote_ip", "")
    rport = event.get("remote_port")

    score, reasons = score_network(rip, rport)

    decision = {
        "allow": True,
        "score": score,
        "reasons": reasons,
        "recommended_action": "allow",
        "type": "net",
        "pid": pid,
        "path": path,
        "remote_ip": rip,
        "remote_port": rport,
        "honeypot_redirect": False,
        "genai_class": "NORMAL",
        "ai_worm_score": 0,
        "ai_worm_suspected": False,
    }

    if score >= RULES["max_score_recommend_quar"]:
        decision["recommended_action"] = "quarantine"
    elif score >= RULES["max_score_recommend_kill"]:
        decision["recommended_action"] = "kill"
    elif score >= RULES["max_score_honeypot"]:
        decision["recommended_action"] = "honeypot"

    if score >= RULES["max_score_honeypot"]:
        decision["honeypot_redirect"] = True

    enc_log(f"NET DECISION pid={pid} ip={rip} port={rport} score={score} rec_action={decision['recommended_action']}", "INFO")
    return decision

def enqueue_decision(decision):
    decision["timestamp"] = time.time()
    PENDING_DECISIONS.append(decision)
    persist_pending()
    enc_log(f"ENQUEUE_DECISION type={decision['type']} pid={decision.get('pid')} rec_action={decision['recommended_action']} aiworm={decision.get('ai_worm_suspected')}", "INFO")

# ----------------- CORE LOOP -----------------

def honeypot_maintenance_loop():
    while True:
        try:
            sanitize_honeypot_state()
            honeypot_gc()
        except Exception as e:
            enc_log(f"HONEYPOT_MAINT_ERROR {e}", "ERROR")
        time.sleep(300)

def core_loop():
    global CORE_STATUS
    CORE_STATUS["state"] = "RUNNING"
    enc_log("CORE START v13", "INFO")
    try:
        init_kernel_stubs()
        init_etw_hooks()
        load_suricata_rules()
        load_ai_worm_signatures()
        start_packet_capture()
        init_ml_model()
        init_honeypot()
        threading.Thread(target=honeypot_maintenance_loop, daemon=True).start()
        threading.Thread(target=swarm_sync_loop, daemon=True).start()
        while True:
            time.sleep(1.0)
    except Exception as e:
        CORE_STATUS["state"] = "ERROR"
        CORE_STATUS["error"] = str(e)
        enc_log(f"CORE ERROR {e}", "ERROR")

# ----------------- WATCHER -----------------

known_pids    = set()
baseline_done = False

def baseline_scan():
    global known_pids, baseline_done
    if baseline_done:
        return
    enc_log("WATCHER BASELINE START", "INFO")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            path = get_proc_path(proc)
            if not path:
                continue
            cmdline    = get_proc_cmdline(proc)
            parent_pid = get_proc_parent(proc)
            event = {
                "type": "exec",
                "pid": proc.pid,
                "path": path,
                "cmdline": cmdline,
                "parent_pid": parent_pid
            }
            decision = core_decide_exec(event)
            if decision.get("honeypot_redirect"):
                profile = "genai" if decision.get("genai_class") != "NORMAL" or decision.get("ai_worm_suspected") else "default"
                honeypot_redirect(event, profile=profile)
            enqueue_decision(decision)
            known_pids.add(proc.pid)
        except Exception:
            continue
    baseline_done = True
    enc_log("WATCHER BASELINE DONE", "INFO")

def monitor_processes():
    global known_pids
    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.pid
                current_pids.add(pid)
                if pid not in known_pids:
                    try:
                        path = get_proc_path(proc)
                        if not path:
                            continue
                        cmdline    = get_proc_cmdline(proc)
                        parent_pid = get_proc_parent(proc)
                        event = {
                            "type": "exec",
                            "pid": pid,
                            "path": path,
                            "cmdline": cmdline,
                            "parent_pid": parent_pid
                        }
                        decision = core_decide_exec(event)
                        if decision.get("honeypot_redirect"):
                            profile = "genai" if decision.get("genai_class") != "NORMAL" or decision.get("ai_worm_suspected") else "default"
                            honeypot_redirect(event, profile=profile)
                        enqueue_decision(decision)
                        known_pids.add(pid)
                    except Exception:
                        continue
            resurrected = known_pids.intersection(current_pids)
            for pid in resurrected:
                try:
                    proc = psutil.Process(pid)
                    path = get_proc_path(proc) or ""
                    track_resurrection(pid, path)
                except Exception:
                    continue
            known_pids = current_pids
        except Exception as e:
            enc_log(f"MONITOR_PROCESSES_ERROR {e}", "ERROR")
        time.sleep(1.0)

def monitor_network():
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                pid = c.pid
                if pid is None:
                    continue
                if c.raddr and c.status == psutil.CONN_ESTABLISHED:
                    try:
                        proc = psutil.Process(pid)
                        path = get_proc_path(proc)
                        if not path:
                            continue
                    except Exception:
                        continue
                    event = {
                        "type": "net",
                        "pid": pid,
                        "path": path,
                        "remote_ip": c.raddr.ip,
                        "remote_port": c.raddr.port
                    }
                    decision = core_decide_net(event)
                    if decision.get("honeypot_redirect"):
                        honeypot_redirect(event, profile="default")
                    enqueue_decision(decision)
        except Exception as e:
            enc_log(f"MONITOR_NETWORK_ERROR {e}", "ERROR")
        time.sleep(1.0)

def watcher_loop():
    global WATCHER_STATUS
    WATCHER_STATUS["state"] = "RUNNING"
    enc_log("WATCHER START", "INFO")
    try:
        baseline_scan()
        threading.Thread(target=monitor_processes, daemon=True).start()
        threading.Thread(target=monitor_network, daemon=True).start()
        while True:
            time.sleep(5.0)
    except Exception as e:
        WATCHER_STATUS["state"] = "ERROR"
        WATCHER_STATUS["error"] = str(e)
        enc_log(f"WATCHER ERROR {e}", "ERROR")

# ----------------- SETTINGS / RULES DIALOGS -----------------

class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; }
            QLabel { color: white; }
            QPlainTextEdit { color: white; background-color: #202020; border: 1px solid #404040; }
            QComboBox { color: white; background-color: #303030; border: 1px solid #505050; }
            QCheckBox { color: white; }
            QSpinBox { color: white; background-color: #202020; border: 1px solid #404040; }
            QDoubleSpinBox { color: white; background-color: #202020; border: 1px solid #404040; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
        """)
        layout = QtWidgets.QFormLayout()
        self.cmb_theme = QtWidgets.QComboBox()
        self.cmb_theme.addItems(["dark", "light"])
        self.cmb_theme.setCurrentText(SETTINGS.get("theme", "dark"))
        self.chk_notify = QtWidgets.QCheckBox("Enable block notifications")
        self.chk_notify.setChecked(SETTINGS.get("notify_blocks", True))
        self.spin_gui = QtWidgets.QSpinBox()
        self.spin_gui.setRange(1000, 60000)
        self.spin_gui.setValue(SETTINGS.get("gui_update_interval_ms", 15000))
        self.spin_overlay_opacity = QtWidgets.QDoubleSpinBox()
        self.spin_overlay_opacity.setRange(0.1, 1.0)
        self.spin_overlay_opacity.setSingleStep(0.05)
        self.spin_overlay_opacity.setValue(SETTINGS.get("codex_overlay_opacity", 0.85))
        self.chk_overlay = QtWidgets.QCheckBox("Enable Codex overlays")
        self.chk_overlay.setChecked(SETTINGS.get("codex_overlay_enabled", True))
        self.txt_swarm = QtWidgets.QPlainTextEdit()
        self.txt_swarm.setPlainText("\n".join(SETTINGS.get("swarm_peers", [])))
        layout.addRow("Theme:", self.cmb_theme)
        layout.addRow(self.chk_notify)
        layout.addRow("GUI update interval (ms):", self.spin_gui)
        layout.addRow("Overlay opacity:", self.spin_overlay_opacity)
        layout.addRow(self.chk_overlay)
        layout.addRow("Swarm peers (one per line):", self.txt_swarm)
        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)
        self.setLayout(layout)

    def get_settings(self):
        peers = [l.strip() for l in self.txt_swarm.toPlainText().splitlines() if l.strip()]
        return {
            "theme": self.cmb_theme.currentText(),
            "auto_quarantine": False,
            "notify_blocks": self.chk_notify.isChecked(),
            "gui_update_interval_ms": self.spin_gui.value(),
            "codex_overlay_opacity": self.spin_overlay_opacity.value(),
            "codex_overlay_enabled": self.chk_overlay.isChecked(),
            "swarm_peers": peers,
        }

class RulesDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Rules")
        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; }
            QLabel { color: white; }
            QPlainTextEdit { color: white; background-color: #202020; border: 1px solid #404040; }
            QSpinBox { color: white; background-color: #202020; border: 1px solid #404040; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
        """)
        layout = QtWidgets.QFormLayout()
        self.txt_paths = QtWidgets.QPlainTextEdit()
        self.txt_paths.setPlainText("\n".join(RULES["blocked_paths"]))
        self.txt_ips = QtWidgets.QPlainTextEdit()
        self.txt_ips.setPlainText("\n".join(RULES["blocked_ips"]))
        self.txt_ports = QtWidgets.QPlainTextEdit()
        self.txt_ports.setPlainText("\n".join(str(p) for p in RULES["blocked_ports"]))
        self.spin_honeypot = QtWidgets.QSpinBox()
        self.spin_honeypot.setRange(0, 200)
        self.spin_honeypot.setValue(RULES["max_score_honeypot"])
        self.spin_kill = QtWidgets.QSpinBox()
        self.spin_kill.setRange(0, 200)
        self.spin_kill.setValue(RULES["max_score_recommend_kill"])
        self.spin_quar = QtWidgets.QSpinBox()
        self.spin_quar.setRange(0, 200)
        self.spin_quar.setValue(RULES["max_score_recommend_quar"])
        layout.addRow("Blocked paths:", self.txt_paths)
        layout.addRow("Blocked IPs:", self.txt_ips)
        layout.addRow("Blocked ports:", self.txt_ports)
        layout.addRow("Score threshold (honeypot):", self.spin_honeypot)
        layout.addRow("Score threshold (recommend kill):", self.spin_kill)
        layout.addRow("Score threshold (recommend quarantine):", self.spin_quar)
        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)
        self.setLayout(layout)

    def get_rules(self):
        paths = [l.strip() for l in self.txt_paths.toPlainText().splitlines() if l.strip()]
        ips   = [l.strip() for l in self.txt_ips.toPlainText().splitlines() if l.strip()]
        ports = []
        for l in self.txt_ports.toPlainText().splitlines():
            l = l.strip()
            if not l:
                continue
            try:
                ports.append(int(l))
            except ValueError:
                continue
        return {
            "blocked_paths": paths,
            "blocked_ips": ips,
            "blocked_ports": ports,
            "blocked_hashes": RULES.get("blocked_hashes", []),
            "suspicious_patterns": RULES.get("suspicious_patterns", []),
            "max_score_honeypot": self.spin_honeypot.value(),
            "max_score_recommend_kill": self.spin_kill.value(),
            "max_score_recommend_quar": self.spin_quar.value()
        }

# ----------------- CODEX CONTROL CONSOLE OVERLAYS -----------------

def add_overlay(name, description, severity):
    CODEX_OVERLAYS[name] = {
        "description": description,
        "severity": severity,
        "created": time.time(),
    }
    persist_overlays()
    enc_log(f"CODEX_OVERLAY_ADD name={name} severity={severity}", "INFO")

def remove_overlay(name):
    if name in CODEX_OVERLAYS:
        del CODEX_OVERLAYS[name]
        persist_overlays()
        enc_log(f"CODEX_OVERLAY_REMOVE name={name}", "INFO")

# ----------------- OPERATOR SCRIPTING CONSOLE -----------------

def run_operator_script(script_text):
    result = {"output": "", "error": ""}
    try:
        local_ctx = {
            "HONEYPOT_STATE": HONEYPOT_STATE,
            "PENDING_DECISIONS": PENDING_DECISIONS,
            "CODEX_OVERLAYS": CODEX_OVERLAYS,
            "RULES": RULES,
            "SETTINGS": SETTINGS,
        }
        exec(script_text, {}, local_ctx)
        result["output"] = "Script executed (context mutated in memory)."
        enc_log("OPERATOR_SCRIPT_EXEC", "INFO")
    except Exception as e:
        result["error"] = str(e)
        enc_log(f"OPERATOR_SCRIPT_ERROR {e}", "ERROR")
    return result

# ----------------- GUI -----------------

class StatusGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Daemon v13 – Mode C Hybrid Honeypot + AI Worm Defenses")
        self.setGeometry(200, 200, 1500, 900)
        self.theme = SETTINGS.get("theme", "dark")
        self.apply_theme()
        main_layout = QtWidgets.QVBoxLayout()

        status_layout = QtWidgets.QHBoxLayout()
        self.lbl_core        = QtWidgets.QLabel("Core: STOPPED")
        self.lbl_watcher     = QtWidgets.QLabel("Watcher: STOPPED")
        self.lbl_core_err    = QtWidgets.QLabel("")
        self.lbl_watcher_err = QtWidgets.QLabel("")
        self.lbl_cpu         = QtWidgets.QLabel("CPU: 0%")
        self.lbl_mem         = QtWidgets.QLabel("Memory: 0%")
        self.lbl_watchdog    = QtWidgets.QLabel("GUI Watchdog: ACTIVE")
        self.lbl_aiworm      = QtWidgets.QLabel("AI Worm Alerts: 0")
        for lbl in [self.lbl_core, self.lbl_watcher, self.lbl_core_err,
                    self.lbl_watcher_err, self.lbl_cpu, self.lbl_mem,
                    self.lbl_watchdog, self.lbl_aiworm]:
            lbl.setStyleSheet("font-size: 13px; color: white;")
            status_layout.addWidget(lbl)
        main_layout.addLayout(status_layout)

        ctrl_layout = QtWidgets.QHBoxLayout()
        self.btn_settings = QtWidgets.QPushButton("Settings")
        self.btn_settings.clicked.connect(self.open_settings)
        self.btn_rules = QtWidgets.QPushButton("Rules")
        self.btn_rules.clicked.connect(self.open_rules)
        self.txt_pid = QtWidgets.QLineEdit()
        self.txt_pid.setPlaceholderText("PID to kill (manual)")
        self.btn_kill = QtWidgets.QPushButton("Kill PID")
        self.btn_kill.clicked.connect(self.kill_pid_from_gui)
        ctrl_layout.addWidget(self.btn_settings)
        ctrl_layout.addWidget(self.btn_rules)
        ctrl_layout.addWidget(self.txt_pid)
        ctrl_layout.addWidget(self.btn_kill)
        main_layout.addLayout(ctrl_layout)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #404040; } "
            "QTabBar::tab { color: white; background: #303030; padding: 6px; } "
            "QTabBar::tab:selected { background: #505050; }"
        )

        # Pending tab
        self.tab_pending = QtWidgets.QWidget()
        ov_layout = QtWidgets.QVBoxLayout()
        self.lst_pending = QtWidgets.QTableWidget()
        self.lst_pending.setColumnCount(8)
        self.lst_pending.setHorizontalHeaderLabels(
            ["Type", "PID", "Path/IP", "Score", "Recommended", "GenAI", "AI Worm", "Action"]
        )
        self.lst_pending.horizontalHeader().setStretchLastSection(True)
        self.lst_pending.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        ov_layout.addWidget(QtWidgets.QLabel("Pending decisions (manual YES/NO):"))
        ov_layout.addWidget(self.lst_pending)
        self.tab_pending.setLayout(ov_layout)

        # Processes tab
        self.tab_processes = QtWidgets.QWidget()
        proc_layout = QtWidgets.QVBoxLayout()
        self.tbl_procs = QtWidgets.QTableWidget()
        self.tbl_procs.setColumnCount(8)
        self.tbl_procs.setHorizontalHeaderLabels(["PID", "Name", "Path", "CPU%", "Mem%", "Parent", "Start", "GenAI Class"])
        self.tbl_procs.horizontalHeader().setStretchLastSection(True)
        self.tbl_procs.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        proc_layout.addWidget(self.tbl_procs)
        self.tab_processes.setLayout(proc_layout)

        # Network tab
        self.tab_network = QtWidgets.QWidget()
        net_layout = QtWidgets.QVBoxLayout()
        self.tbl_net = QtWidgets.QTableWidget()
        self.tbl_net.setColumnCount(6)
        self.tbl_net.setHorizontalHeaderLabels(["PID", "Process", "Local", "Remote", "Status", "Family"])
        self.tbl_net.horizontalHeader().setStretchLastSection(True)
        self.tbl_net.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        net_layout.addWidget(self.tbl_net)
        self.tab_network.setLayout(net_layout)

        # Rules view tab
        self.tab_rules_view = QtWidgets.QWidget()
        rv_layout = QtWidgets.QVBoxLayout()
        self.txt_rules_view = QtWidgets.QTextEdit()
        self.txt_rules_view.setReadOnly(True)
        self.txt_rules_view.setStyleSheet("color: white; background-color: #202020;")
        rv_layout.addWidget(QtWidgets.QLabel("Current rules (JSON):"))
        rv_layout.addWidget(self.txt_rules_view)
        self.tab_rules_view.setLayout(rv_layout)

        # Logs tab
        self.tab_logs = QtWidgets.QWidget()
        logs_layout = QtWidgets.QVBoxLayout()
        self.txt_logs = QtWidgets.QTextEdit()
        self.txt_logs.setReadOnly(True)
        self.txt_logs.setStyleSheet("color: white; background-color: #202020;")
        logs_layout.addWidget(QtWidgets.QLabel("Logs (decrypted):"))
        logs_layout.addWidget(self.txt_logs)
        self.tab_logs.setLayout(logs_layout)

        # Honeypot tab
        self.tab_honeypot = QtWidgets.QWidget()
        hp_layout = QtWidgets.QVBoxLayout()
        self.tbl_honeypot = QtWidgets.QTableWidget()
        self.tbl_honeypot.setColumnCount(7)
        self.tbl_honeypot.setHorizontalHeaderLabels(
            ["Session ID", "Type", "PID", "Path/IP", "Status", "Actions", "Profile"]
        )
        self.tbl_honeypot.horizontalHeader().setStretchLastSection(True)
        self.tbl_honeypot.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        self.tbl_honeypot.itemDoubleClicked.connect(self.open_honeypot_session_viewer)
        hp_layout.addWidget(QtWidgets.QLabel("Honeypot sessions (double-click to replay):"))
        hp_layout.addWidget(self.tbl_honeypot)
        self.tab_honeypot.setLayout(hp_layout)

        # Codex overlays tab
        self.tab_overlays = QtWidgets.QWidget()
        ovl_layout = QtWidgets.QVBoxLayout()
        self.tbl_overlays = QtWidgets.QTableWidget()
        self.tbl_overlays.setColumnCount(4)
        self.tbl_overlays.setHorizontalHeaderLabels(
            ["Name", "Description", "Severity", "Created"]
        )
        self.tbl_overlays.horizontalHeader().setStretchLastSection(True)
        self.tbl_overlays.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        ovl_layout.addWidget(QtWidgets.QLabel("Codex Control Console Overlays:"))
        ovl_layout.addWidget(self.tbl_overlays)
        self.tab_overlays.setLayout(ovl_layout)

        # Operator scripting tab
        self.tab_script = QtWidgets.QWidget()
        sc_layout = QtWidgets.QVBoxLayout()
        self.txt_script = QtWidgets.QPlainTextEdit()
        self.txt_script.setStyleSheet("color: white; background-color: #202020;")
        self.btn_run_script = QtWidgets.QPushButton("Run Script")
        self.btn_run_script.clicked.connect(self.run_script_from_gui)
        self.txt_script_output = QtWidgets.QTextEdit()
        self.txt_script_output.setReadOnly(True)
        self.txt_script_output.setStyleSheet("color: white; background-color: #202020;")
        sc_layout.addWidget(QtWidgets.QLabel("Operator scripting console (Python, limited context):"))
        sc_layout.addWidget(self.txt_script)
        sc_layout.addWidget(self.btn_run_script)
        sc_layout.addWidget(QtWidgets.QLabel("Script output:"))
        sc_layout.addWidget(self.txt_script_output)
        self.tab_script.setLayout(sc_layout)

        self.tabs.addTab(self.tab_pending, "Pending")
        self.tabs.addTab(self.tab_processes, "Processes")
        self.tabs.addTab(self.tab_network, "Network")
        self.tabs.addTab(self.tab_rules_view, "Rules")
        self.tabs.addTab(self.tab_logs, "Logs")
        self.tabs.addTab(self.tab_honeypot, "Honeypot")
        self.tabs.addTab(self.tab_overlays, "Overlays")
        self.tabs.addTab(self.tab_script, "Operator Console")

        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        interval = SETTINGS.get("gui_update_interval_ms", 15000)

        self.timer_status = QtCore.QTimer()
        self.timer_status.timeout.connect(self.update_status)
        self.timer_status.start(1000)

        self.timer_logs = QtCore.QTimer()
        self.timer_logs.timeout.connect(self.update_logs)
        self.timer_logs.start(interval)

        self.timer_stats = QtCore.QTimer()
        self.timer_stats.timeout.connect(self.update_stats)
        self.timer_stats.start(1000)

        self.timer_procs = QtCore.QTimer()
        self.timer_procs.timeout.connect(self.update_process_table)
        self.timer_procs.start(interval)

        self.timer_net = QtCore.QTimer()
        self.timer_net.timeout.connect(self.update_network_table)
        self.timer_net.start(interval)

        self.timer_rules_view = QtCore.QTimer()
        self.timer_rules_view.timeout.connect(self.update_rules_view)
        self.timer_rules_view.start(interval)

        self.timer_pending = QtCore.QTimer()
        self.timer_pending.timeout.connect(self.update_pending_table)
        self.timer_pending.start(interval)

        self.timer_honeypot = QtCore.QTimer()
        self.timer_honeypot.timeout.connect(self.update_honeypot_table)
        self.timer_honeypot.start(interval)

        self.timer_overlays = QtCore.QTimer()
        self.timer_overlays.timeout.connect(self.update_overlays_table)
        self.timer_overlays.start(interval)

        self.watchdog_timer = QtCore.QTimer()
        self.watchdog_timer.timeout.connect(self.gui_watchdog)
        self.watchdog_timer.start(2000)

    def apply_theme(self):
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(25, 25, 25))
        palette.setColor(QtGui.QPalette.ColorRole.WindowText, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Base, QtGui.QColor(20, 20, 20))
        palette.setColor(QtGui.QPalette.ColorRole.Text, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Button, QtGui.QColor(40, 40, 40))
        palette.setColor(QtGui.QPalette.ColorRole.ButtonText, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Highlight, QtGui.QColor(0, 120, 215))
        palette.setColor(QtGui.QPalette.ColorRole.HighlightedText, QtGui.QColor(255, 255, 255))
        self.setPalette(palette)
        self.setStyleSheet("""
            QLabel { color: white; }
            QLineEdit { color: white; background-color: #202020; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
            QSplitter::handle { background-color: #303030; }
        """)

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            new_s = dlg.get_settings()
            SETTINGS.update(new_s)
            save_json(SETTINGS_PATH, SETTINGS)
            self.theme = SETTINGS.get("theme", "dark")
            self.apply_theme()
            interval = SETTINGS.get("gui_update_interval_ms", 15000)
            self.timer_logs.setInterval(interval)
            self.timer_procs.setInterval(interval)
            self.timer_net.setInterval(interval)
            self.timer_rules_view.setInterval(interval)
            self.timer_pending.setInterval(interval)
            self.timer_honeypot.setInterval(interval)
            self.timer_overlays.setInterval(interval)

    def open_rules(self):
        dlg = RulesDialog(self)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            new_r = dlg.get_rules()
            RULES.update(new_r)
            save_json(RULES_PATH, RULES)

    def kill_pid_from_gui(self):
        pid_text = self.txt_pid.text().strip()
        if not pid_text.isdigit():
            return
        pid = int(pid_text)
        kill_pid(pid)

    def update_status(self):
        self.lbl_core.setText(f"Core: {CORE_STATUS['state']}")
        self.lbl_watcher.setText(f"Watcher: {WATCHER_STATUS['state']}")
        self.lbl_core_err.setText(f"Core error: {CORE_STATUS['error']}")
        self.lbl_watcher_err.setText(f"Watcher error: {WATCHER_STATUS['error']}")

    def update_logs(self):
        logs = tail_decrypted_logs()
        self.txt_logs.clear()
        aiworm_count = 0
        for line in logs:
            self.txt_logs.append(line)
            if "aiworm" in line.lower():
                aiworm_count += 1
        self.lbl_aiworm.setText(f"AI Worm Alerts: {aiworm_count}")

    def update_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.lbl_cpu.setText(f"CPU: {cpu:.1f}%")
        self.lbl_mem.setText(f"Memory: {mem:.1f}%")

    def update_process_table(self):
        procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid    = proc.pid
                name   = proc.info.get("name", "")
                path   = get_proc_path(proc) or ""
                cpu    = proc.cpu_percent(interval=None)
                mem    = proc.memory_percent()
                parent = get_proc_parent(proc)
                start  = get_proc_create_time(proc)
                genai  = classify_genai_process(path, get_proc_cmdline(proc))
                procs.append((pid, name, path, cpu, mem, parent, start, genai))
            except Exception:
                continue
        self.tbl_procs.setRowCount(len(procs))
        for row, (pid, name, path, cpu, mem, parent, start, genai) in enumerate(procs):
            self.tbl_procs.setItem(row, 0, QtWidgets.QTableWidgetItem(str(pid)))
            self.tbl_procs.setItem(row, 1, QtWidgets.QTableWidgetItem(name))
            self.tbl_procs.setItem(row, 2, QtWidgets.QTableWidgetItem(path))
            self.tbl_procs.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{cpu:.1f}"))
            self.tbl_procs.setItem(row, 4, QtWidgets.QTableWidgetItem(f"{mem:.1f}"))
            self.tbl_procs.setItem(row, 5, QtWidgets.QTableWidgetItem(str(parent)))
            self.tbl_procs.setItem(row, 6, QtWidgets.QTableWidgetItem(start))
            self.tbl_procs.setItem(row, 7, QtWidgets.QTableWidgetItem(genai))

    def update_network_table(self):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                pid = c.pid
                if pid is None:
                    continue
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                except Exception:
                    name = "?"
                laddr  = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr  = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                status = c.status
                family = str(c.family)
                conns.append((pid, name, laddr, raddr, status, family))
        except Exception:
            pass
        self.tbl_net.setRowCount(len(conns))
        for row, (pid, name, laddr, raddr, status, family) in enumerate(conns):
            self.tbl_net.setItem(row, 0, QtWidgets.QTableWidgetItem(str(pid)))
            self.tbl_net.setItem(row, 1, QtWidgets.QTableWidgetItem(name))
            self.tbl_net.setItem(row, 2, QtWidgets.QTableWidgetItem(laddr))
            self.tbl_net.setItem(row, 3, QtWidgets.QTableWidgetItem(raddr))
            self.tbl_net.setItem(row, 4, QtWidgets.QTableWidgetItem(status))
            self.tbl_net.setItem(row, 5, QtWidgets.QTableWidgetItem(family))

    def update_rules_view(self):
        self.txt_rules_view.clear()
        self.txt_rules_view.append(json.dumps(RULES, indent=2))

    def update_pending_table(self):
        self.lst_pending.setRowCount(len(PENDING_DECISIONS))
        for row, dec in enumerate(PENDING_DECISIONS):
            dtype = dec.get("type", "")
            pid   = dec.get("pid", "")
            score = dec.get("score", 0)
            rec   = dec.get("recommended_action", "")
            genai = dec.get("genai_class", "NORMAL")
            aiw   = dec.get("ai_worm_score", 0)
            ts    = datetime.fromtimestamp(dec.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
            if dtype == "exec":
                path_ip = dec.get("path", "")
            else:
                path_ip = f"{dec.get('remote_ip', '')}:{dec.get('remote_port', '')}"
            self.lst_pending.setItem(row, 0, QtWidgets.QTableWidgetItem(dtype))
            self.lst_pending.setItem(row, 1, QtWidgets.QTableWidgetItem(str(pid)))
            self.lst_pending.setItem(row, 2, QtWidgets.QTableWidgetItem(path_ip))
            self.lst_pending.setItem(row, 3, QtWidgets.QTableWidgetItem(str(score)))
            self.lst_pending.setItem(row, 4, QtWidgets.QTableWidgetItem(rec))
            self.lst_pending.setItem(row, 5, QtWidgets.QTableWidgetItem(genai))
            self.lst_pending.setItem(row, 6, QtWidgets.QTableWidgetItem(str(aiw)))
            btn_widget = QtWidgets.QWidget()
            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.setContentsMargins(0, 0, 0, 0)
            btn_kill = QtWidgets.QPushButton("Kill")
            btn_quar = QtWidgets.QPushButton("Quarantine")
            btn_ignore = QtWidgets.QPushButton("Ignore")
            btn_kill.clicked.connect(lambda _, r=row: self.perform_action(r, "kill"))
            btn_quar.clicked.connect(lambda _, r=row: self.perform_action(r, "quarantine"))
            btn_ignore.clicked.connect(lambda _, r=row: self.perform_action(r, "ignore"))
            btn_layout.addWidget(btn_kill)
            btn_layout.addWidget(btn_quar)
            btn_layout.addWidget(btn_ignore)
            btn_widget.setLayout(btn_layout)
            self.lst_pending.setCellWidget(row, 7, btn_widget)

    def perform_action(self, row, action):
        if row < 0 or row >= len(PENDING_DECISIONS):
            return
        dec = PENDING_DECISIONS[row]
        pid = dec.get("pid")
        path = dec.get("path", "")
        if action == "kill":
            if pid is not None:
                kill_pid(pid)
                enc_log(f"MANUAL_KILL pid={pid} path={path}", "WARN")
        elif action == "quarantine":
            if pid is not None:
                kill_pid(pid)
            if path:
                qpath = quarantine_file(path)
                enc_log(f"MANUAL_QUAR pid={pid} path={path} qpath={qpath}", "WARN")
        elif action == "ignore":
            enc_log(f"MANUAL_IGNORE pid={pid} path={path}", "INFO")
        del PENDING_DECISIONS[row]
        persist_pending()
        self.update_pending_table()

    def update_honeypot_table(self):
        sanitize_honeypot_state()
        sessions = []
        for sid, sess in HONEYPOT_STATE.items():
            if sid == "honeypot_meta":
                continue
            if not isinstance(sess, dict):
                enc_log(f"HONEYPOT_CORRUPT_ENTRY sid={sid} type={type(sess)}", "ERROR")
                continue
            sessions.append((sid, sess))
        self.tbl_honeypot.setRowCount(len(sessions))
        for row, (sid, sess) in enumerate(sessions):
            etype = sess.get("event_type", "")
            pid   = sess.get("pid", "")
            path  = sess.get("path", "") or f"{sess.get('remote_ip','')}:{sess.get('remote_port','')}"
            status = sess.get("status", "active")
            actions = len(sess.get("actions", []))
            profile = sess.get("profile", "default")
            self.tbl_honeypot.setItem(row, 0, QtWidgets.QTableWidgetItem(sid))
            self.tbl_honeypot.setItem(row, 1, QtWidgets.QTableWidgetItem(etype))
            self.tbl_honeypot.setItem(row, 2, QtWidgets.QTableWidgetItem(str(pid)))
            self.tbl_honeypot.setItem(row, 3, QtWidgets.QTableWidgetItem(path))
            self.tbl_honeypot.setItem(row, 4, QtWidgets.QTableWidgetItem(status))
            self.tbl_honeypot.setItem(row, 5, QtWidgets.QTableWidgetItem(str(actions)))
            self.tbl_honeypot.setItem(row, 6, QtWidgets.QTableWidgetItem(profile))

    def update_overlays_table(self):
        self.tbl_overlays.setRowCount(len(CODEX_OVERLAYS))
        for row, (name, ov) in enumerate(CODEX_OVERLAYS.items()):
            desc = ov.get("description", "")
            sev  = ov.get("severity", "")
            ts   = datetime.fromtimestamp(ov.get("created", time.time())).strftime("%Y-%m-%d %H:%M:%S")
            self.tbl_overlays.setItem(row, 0, QtWidgets.QTableWidgetItem(name))
            self.tbl_overlays.setItem(row, 1, QtWidgets.QTableWidgetItem(desc))
            self.tbl_overlays.setItem(row, 2, QtWidgets.QTableWidgetItem(str(sev)))
            self.tbl_overlays.setItem(row, 3, QtWidgets.QTableWidgetItem(ts))

    def gui_watchdog(self):
        if not self.isVisible():
            self.show()
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()
        self.lbl_watchdog.setText("GUI Watchdog: ACTIVE")

    def closeEvent(self, event: QtGui.QCloseEvent):
        event.ignore()
        self.showMinimized()
        enc_log("GUI_CLOSE_ATTEMPT blocked by watchdog", "WARN")

    def run_script_from_gui(self):
        script = self.txt_script.toPlainText()
        result = run_operator_script(script)
        self.txt_script_output.clear()
        if result["error"]:
            self.txt_script_output.append(f"ERROR: {result['error']}")
        else:
            self.txt_script_output.append(result["output"])

    def open_honeypot_session_viewer(self, item):
        row = item.row()
        sid_item = self.tbl_honeypot.item(row, 0)
        if not sid_item:
            return
        sid = sid_item.text()
        sess = HONEYPOT_STATE.get(sid)
        if not isinstance(sess, dict):
            return
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(f"Honeypot Session Replay – {sid}")
        dlg.setStyleSheet("QDialog { background-color: #1e1e1e; } QLabel { color: white; } QTextEdit { color: white; background-color: #202020; }")
        layout = QtWidgets.QVBoxLayout()
        txt = QtWidgets.QTextEdit()
        txt.setReadOnly(True)
        actions = sess.get("actions", [])
        for act in actions:
            ts = datetime.fromtimestamp(act.get("ts", time.time())).strftime("%Y-%m-%d %H:%M:%S")
            txt.append(f"[{ts}] {act.get('action')} -> {act.get('details')}")
        layout.addWidget(txt)
        btn_export = QtWidgets.QPushButton("Export Forensics")
        btn_export.clicked.connect(lambda: self.export_forensics_and_notify(sid))
        layout.addWidget(btn_export)
        dlg.setLayout(layout)
        dlg.resize(800, 400)
        dlg.exec()

    def export_forensics_and_notify(self, sid):
        fname = honeypot_forensic_export(sid)
        if fname:
            QtWidgets.QMessageBox.information(self, "Forensics Export", f"Exported to:\n{fname}")
        else:
            QtWidgets.QMessageBox.warning(self, "Forensics Export", "Failed to export session.")

# ----------------- ENTRY POINT -----------------

def run_gui():
    app = QtWidgets.QApplication(sys.argv)
    gui = StatusGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    threading.Thread(target=core_loop, daemon=True).start()
    threading.Thread(target=watcher_loop, daemon=True).start()
    run_gui()
