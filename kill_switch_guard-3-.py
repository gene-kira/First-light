from collections import deque
import hashlib
import json
import os
import platform
import random
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import uuid


# =========================
# 📦 Library Autoloader
# =========================

REQUIRED_PACKAGES = ["psutil"]


def autoload_dependencies(packages: list[str] | None = None) -> dict[str, bool]:
    pkgs = packages or REQUIRED_PACKAGES
    status: dict[str, bool] = {}
    for pkg in pkgs:
        try:
            __import__(pkg)
            status[pkg] = True
        except ImportError:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    timeout=60,
                )
                __import__(pkg)
                status[pkg] = True
            except Exception:
                status[pkg] = False
    return status


DEP_STATUS = autoload_dependencies(REQUIRED_PACKAGES)
try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore


# =========================
# ⚙️ Constants & Paths
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST_FILE = os.path.join(BASE_DIR, "guardian_allowlist.json")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "guardian_blocklist.json")
WEIGHTS_FILE = os.path.join(BASE_DIR, "guard_weights.json")
AUDIT_FILE = os.path.join(BASE_DIR, "guard_audit.jsonl")
SNAPSHOT_FILE = os.path.join(BASE_DIR, "guard_snapshot.json")

DEFAULT_PATTERNS = [
    "metasploit",
    "msfconsole",
    "msfrpcd",
    "msfvenom",
    "agent",
    "nmap",
    "masscan",
    "powershell",
]
DEFAULT_ALLOWLIST_PATTERNS = ["python", "code", "cursor", "bash", "zsh", "systemd", "explorer.exe"]

DEFAULT_WEIGHTS = {
    "pattern_match": 0.30,
    "cpu_spike": 0.12,
    "mem_growth": 0.10,
    "spawn_velocity": 0.13,
    "disk_io": 0.13,
    "net_activity": 0.10,
    "chain_consensus": 0.12,
    "auto_stop_threshold": 0.85,
}

PRIVATE_NETS = [
    ("10.",),
    ("172.", range(16, 32)),
    ("192.168.",),
]

REMOTE_TOOL_PATTERNS = re.compile(
    r"(teamviewer|anydesk|vnc|remote|rdp|shadow|splashtop|ultraviewer|ammyy|logmein)",
    re.IGNORECASE,
)

FIREWALL_CMD_PATTERNS = re.compile(
    r"(netsh\s+advfirewall|Set-NetFirewall|New-NetFirewall|ufw\s+enable|ufw\s+disable)",
    re.IGNORECASE,
)

SETTINGS_CMD_PATTERNS = re.compile(
    r"(reg\s+add|reg\s+delete|powershell\s+Set-ItemProperty|gpedit\.msc|secpol\.msc)",
    re.IGNORECASE,
)

SHELL_NAMES = re.compile(
    r"(cmd\.exe|powershell\.exe|pwsh\.exe|bash\.exe|wsl\.exe)",
    re.IGNORECASE,
)

SUSPICIOUS_PROC_PATTERNS = re.compile(
    r"(keylogger|sniffer|injector|bot|miner)",
    re.IGNORECASE,
)


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("127.") or ip == "::1" or ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                second = int(parts[1])
                return 16 <= second <= 31
            except ValueError:
                return False
    return False


# =========================
# 🦎 Glyph, Mirror, Flip & Chameleon Codec + Shredder
# =========================

GLYPH_ALPHABET = "◈◇❖✦✧⬟⬢⬡△▽◁▷◐◑◒◓☖☗☀☁☂★☆☉☊☋☌☍"
# Build a one-to-one mirror map. The previous source/target strings had
# different lengths, which raised ValueError during module import. Some glyphs
# in the legacy target are repeated or map back to ordinary ASCII; skip those
# entries so unmirror_and_reverse_text() can reliably invert the mapping.
_FLIP_SOURCE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@:+/ "
_FLIP_TARGET = "ɐqɔpǝɟƃɥᴉɾʞlɯuodbɹsʇnʌʍxʎ∀ᙠƆᗡƎᖟ⅁HIſʞ˥WNOԀQRSd⊥∩ΛMX⅄0123456789‾˙_@:+/·"
_flip_pairs: list[tuple[str, str]] = []
_used_flip_targets: set[str] = set()
for _source_char, _target_char in zip(_FLIP_SOURCE, _FLIP_TARGET):
    if ord(_target_char) > 127 and _target_char not in _used_flip_targets:
        _flip_pairs.append((_source_char, _target_char))
        _used_flip_targets.add(_target_char)
FLIP_MAP = str.maketrans(
    "".join(source for source, _target in _flip_pairs),
    "".join(target for _source, target in _flip_pairs),
)
del _source_char, _target_char, _flip_pairs, _used_flip_targets


def reverse_and_mirror_text(text: str) -> str:
    """Reverses character sequence and applies mirror/upside-down character mapping."""
    mirrored = text.translate(FLIP_MAP)
    return mirrored[::-1]


def unmirror_and_reverse_text(mirrored_text: str) -> str:
    """Restores text produced by reverse_and_mirror_text."""
    inv_map = {v: k for k, v in FLIP_MAP.items() if chr(k) not in inv_collisions()}
    restored = mirrored_text[::-1].translate(inv_map)
    return restored


def inv_collisions() -> set[str]:
    seen: set[str] = set()
    dups: set[str] = set()
    for _k, v in FLIP_MAP.items():
        ch = chr(v)
        if ch in seen:
            dups.add(ch)
        seen.add(ch)
    return dups


def glyph_encode(text: str) -> str:
    """Encodes UTF-8 bytes into base-28 glyph symbols."""
    raw = text.encode("utf-8")
    if not raw:
        return ""
    num = int.from_bytes(raw, "big")
    base = len(GLYPH_ALPHABET)
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, base)
        chars.append(GLYPH_ALPHABET[rem])
    length_tag = f"[{len(raw)}:"
    return length_tag + "".join(reversed(chars)) + "]"


def glyph_decode(encoded: str) -> str:
    """Decodes glyph_encode output back to plain text."""
    s = encoded.strip()
    # glyph_encode intentionally represents the empty string as an empty stream.
    if not s:
        return ""
    if not (s.startswith("[") and s.endswith("]") and ":" in s):
        raise ValueError("Invalid glyph format")
    prefix, body = s[1:-1].split(":", 1)
    byte_len = int(prefix)
    base = len(GLYPH_ALPHABET)
    num = 0
    for ch in body:
        idx = GLYPH_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"Unknown glyph character: {ch}")
        num = num * base + idx
    raw = num.to_bytes(byte_len, "big")
    return raw.decode("utf-8", errors="replace")


def chameleon_mask(value: str, salt: str = "guardian-chameleon") -> str:
    """Produces a deterministic chameleon alias for an identifier/field."""
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:12]
    return f"chameleon://{digest}"


def protect_sensitive_bundle(phone: str, biometric_id: str, mac_addr: str, telemetry: str) -> dict:
    """Applies reverse/flip/mirror, glyph encoding, and chameleon masking to sensitive fields."""
    bundle = {
        "phone": phone,
        "biometric": biometric_id,
        "mac": mac_addr,
        "telemetry": telemetry,
    }
    protected: dict[str, dict[str, str]] = {}
    for field_name, val in bundle.items():
        flipped = reverse_and_mirror_text(val)
        glyphs = glyph_encode(flipped)
        alias = chameleon_mask(val, salt=field_name)
        protected[field_name] = {
            "chameleon_alias": alias,
            "flipped_mirror": flipped,
            "glyph_stream": glyphs,
        }
    return protected


def shred_file(filepath: str, passes: int = 3) -> tuple[bool, str]:
    """Overwrites file contents across passes before removing it from disk."""
    abs_path = os.path.abspath(filepath)
    if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
        return False, f"File not found: {abs_path}"
    try:
        size = os.path.getsize(abs_path)
        with open(abs_path, "r+b") as f:
            for p in range(max(1, passes)):
                f.seek(0)
                if p % 3 == 0:
                    data = b"\x00" * size
                elif p % 3 == 1:
                    data = os.urandom(size)
                else:
                    data = b"\xff" * size
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        os.remove(abs_path)
        return True, f"Shredded ({passes} passes) and removed: {abs_path}"
    except Exception as exc:
        return False, f"Failed to shred {abs_path}: {exc}"


# =========================
# 📡 Real-Time Identifiers & Telemetry
# =========================

brain_lock = threading.Lock()
brain_state: dict = {
    "swarm_id": None,
    "phantom_history": [],
}


def get_real_mac() -> str:
    if psutil is not None:
        try:
            for _iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    af_link = getattr(psutil, "AF_LINK", None)
                    if af_link is not None and addr.family == af_link:
                        return str(addr.address)
                    if getattr(addr.family, "name", "") == "AF_LINK":
                        return str(addr.address)
        except Exception:
            pass
    mac_int = uuid.getnode()
    return ":".join(f"{(mac_int >> ele) & 0xFF:02x}" for ele in range(40, -1, -8))


def get_real_ip() -> tuple[str, str]:
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        try:
            public_ip = socket.gethostbyname_ex(hostname)[2][-1]
        except Exception:
            public_ip = local_ip
        return local_ip, public_ip
    except Exception as exc:
        return "IP error", str(exc)


def get_telemetry() -> tuple[str, str]:
    os_info = platform.platform()
    machine_fp = f"{platform.system()}-{platform.machine()}-{platform.processor() or 'generic'}"
    return os_info, machine_fp


def get_swarm_id() -> str:
    with brain_lock:
        if brain_state.get("swarm_id"):
            return str(brain_state["swarm_id"])
    sid = str(uuid.getnode())
    with brain_lock:
        brain_state["swarm_id"] = sid
    return sid


def synthesize_phantom() -> str:
    entropy = uuid.uuid4().hex + str(time.time_ns())
    phantom = f"phantom://{entropy[:12]}"
    with brain_lock:
        hist = brain_state.setdefault("phantom_history", [])
        hist.append(phantom)
        brain_state["phantom_history"] = hist[-50:]
    return phantom


# =========================
# 🧠 Consensus, Chain, EventBus, Belief & Flow Engines
# =========================

class SecEvent:
    def __init__(self, etype: str, entity: str, meta: dict | None = None) -> None:
        self.ts = time.time()
        self.type = etype
        self.entity = entity
        self.meta = meta or {}


class EventBus:
    def __init__(self) -> None:
        self.subscribers: list = []
        self.queue: deque[SecEvent] = deque()

    def publish(self, event: SecEvent) -> None:
        self.queue.append(event)

    def subscribe(self, fn) -> None:
        self.subscribers.append(fn)

    def drain(self, max_items: int = 200) -> int:
        processed = 0
        while self.queue and processed < max_items:
            evt = self.queue.popleft()
            for fn in list(self.subscribers):
                try:
                    fn(evt)
                except Exception:
                    pass
            processed += 1
        return processed


class Queen:
    """Consensus engine aggregating entity risk reports across observer nodes."""

    def __init__(self) -> None:
        self.nodes: dict[str, list[dict]] = {}

    def update(self, node: str, events: list[dict]) -> None:
        self.nodes[node] = events

    def global_risk(self, threshold: float = 1.5) -> dict[str, float]:
        risk: dict[str, float] = {}
        for _node, evts in self.nodes.items():
            for e in evts:
                entity = str(e.get("entity", ""))
                if not entity:
                    continue
                risk[entity] = risk.get(entity, 0.0) + float(e.get("score", 0.0))
        return {k: round(v, 4) for k, v in risk.items() if v > threshold}


class AttackChainEngine:
    """Sliding-window behavioral sequence detector supporting SecEvent and raw tuples."""

    def __init__(self, window: float = 120.0) -> None:
        self.events: deque[tuple[float, str, str, dict]] = deque()
        self.window = window

    def ingest(self, evt: SecEvent) -> None:
        self.events.append((evt.ts, evt.type, evt.entity, evt.meta))
        self._cleanup(evt.ts)

    def add_event(self, event_type: str, data: dict | None = None, entity: str = "") -> None:
        now = time.time()
        payload = data or {}
        ent = entity or str(payload.get("name") or payload.get("ip") or event_type)
        self.events.append((now, event_type, ent, payload))
        self._cleanup(now)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def detect(self) -> list[tuple[str, float]]:
        self._cleanup(time.time())
        types = [e[1] for e in self.events]
        entities_and_meta = " ".join(f"{e[1]} {e[2]} {e[3]}" for e in self.events).lower()
        chains: list[tuple[str, float]] = []

        has_proc = ("proc_start" in types) or ("proc_spawn" in types)
        has_net = ("net_conn" in types) or ("net_connect" in types)
        has_file = ("file_mod" in types) or ("disk_surge" in types)
        has_ps = ("powershell" in types) or ("powershell" in entities_and_meta)

        if has_proc and has_net and has_file:
            chains.append(("FULL_ATTACK_CHAIN", 0.95))
        if has_proc and has_ps and has_net:
            chains.append(("LOLBIN_ATTACK", 0.90))
        if has_net and has_ps:
            chains.append(("LOLBIN_BEACON", 0.90))
        if types.count("proc_start") > 10 or (types.count("proc_spawn") > 5 and has_net):
            chains.append(("PROCESS_STORM", 0.82))
        if has_file and has_net:
            chains.append(("PERSISTENCE_EXFIL", 0.85))

        return chains

    def detect_chains(self) -> list[tuple[str, float]]:
        return self.detect()


class ProbabilisticField:
    """Bayesian-style estimator tracking best-guess mean and shrinking variance."""

    def __init__(self, mean: float = 0.25, var: float = 0.15) -> None:
        self.mean = float(mean)
        self.var = max(1e-6, float(var))

    def sample(self) -> float:
        return random.gauss(self.mean, self.var ** 0.5)

    def update(self, observation: float, weight: float = 1.0) -> float:
        w = max(0.01, float(weight))
        obs = max(0.0, min(1.0, float(observation)))
        self.mean = max(0.0, min(1.0, (self.mean + w * obs) / (1.0 + w)))
        self.var = max(1e-6, self.var * 0.90)
        return self.mean


class FlowPhysicsEngine:
    """Models telemetry flow rate, pressure, and damping to classify operational regimes."""

    def __init__(self, damping: float = 0.75) -> None:
        self.damping = max(0.1, min(0.99, damping))
        self.pressure = 0.0
        self.prev_pressure = 0.0
        self.pressure_delta = 0.0
        self.flow_rate = 0.0
        self.regime = "CALM"

    def step(self, event_rate_per_sec: float, max_entity_risk: float, chain_count: int) -> str:
        instant_flow = event_rate_per_sec + (max_entity_risk * 2.0) + (chain_count * 1.5)
        self.flow_rate = (self.flow_rate * self.damping) + (instant_flow * (1.0 - self.damping))
        self.prev_pressure = self.pressure
        self.pressure = max(0.0, (self.pressure * self.damping) + (instant_flow * 0.35))
        self.pressure_delta = self.pressure - self.prev_pressure

        if self.pressure >= 2.2 or chain_count >= 2:
            self.regime = "TURBULENCE"
        elif self.pressure >= 1.0 or self.flow_rate >= 1.5:
            self.regime = "ELEVATED_FLOW"
        else:
            self.regime = "CALM"
        return self.regime


# =========================
# 🔒 Allow / Block Lists & Guard Controller
# =========================

class AutonomousGuardianGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Guardian Autonomous — Glyph/Chameleon Protection, Policy & Predictive Guard")
        self.root.geometry("1120x820")

        self.allow_list: list[dict[str, str]] = []
        self.block_list: list[dict[str, str]] = []
        self.allow_block_lock = threading.Lock()

        self.trust_config: dict = {"strict_local_operator": True, "auto_block_on_kill": True}
        self.policy: dict = {
            "block_remote_control": True,
            "block_firewall_changes": True,
            "block_settings_changes": True,
            "block_suspicious_procs": True,
        }

        self.weights = self.load_weights()
        self.history: dict[int, dict[str, float]] = {}
        self.respawn_events: dict[str, list[float]] = {}
        self.belief_fields: dict[str, ProbabilisticField] = {}
        self.last_scan_results: list[dict] = []
        self.watchdog_ts: dict[str, float] = {}

        self.watch_job: str | None = None
        self.policy_job: str | None = None
        self.net_job: str | None = None
        self.threat_job: str | None = None
        self.self_check_job: str | None = None
        self.bus_job: str | None = None

        self.last_activity_ts: float = time.time()
        self.active_chameleon_token: str = synthesize_phantom()

        self.bus = EventBus()
        self.queen = Queen()
        self.chain = AttackChainEngine(window=120.0)
        self.flow_engine = FlowPhysicsEngine(damping=0.75)
        self.bus.subscribe(self._on_bus_event)

        self.load_lists()
        self._build_ui()

        self.root.bind_all("<Any-KeyPress>", self._mark_user_active, add="+")
        self.root.bind_all("<Any-Button>", self._mark_user_active, add="+")
        self.root.bind_all("<Motion>", self._mark_user_active, add="+")

        self.log(f"Autoloader status: {DEP_STATUS}")
        if psutil is None:
            self.log("Warning: psutil unavailable; process/socket telemetry will use reduced fallback.")
        self.log("Ready. Only use on systems, files, and networks you own or are authorized to test.")
        self.log(f"Allowlist: {ALLOWLIST_FILE} | Blocklist: {BLOCKLIST_FILE} | Weights: {WEIGHTS_FILE}")

        self._schedule_bus_pump()
        self.scan_processes()
        self.monitor_processes()
        self.monitor_network()
        self.threat_scan_and_respond()
        self.self_check()

    # --- Allow / Block List Persistence ---
    def load_lists(self) -> None:
        with self.allow_block_lock:
            if os.path.exists(ALLOWLIST_FILE):
                try:
                    with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
                        self.allow_list = json.load(f)
                except Exception:
                    self.allow_list = []
            if os.path.exists(BLOCKLIST_FILE):
                try:
                    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
                        self.block_list = json.load(f)
                except Exception:
                    self.block_list = []

    def save_lists(self) -> None:
        with self.allow_block_lock:
            try:
                with open(ALLOWLIST_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.allow_list, f, indent=2)
            except Exception:
                pass
            try:
                with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.block_list, f, indent=2)
            except Exception:
                pass

    @staticmethod
    def normalize_entry(name: str, path: str) -> dict[str, str]:
        return {"name": (name or "").lower(), "path": (path or "").lower()}

    @staticmethod
    def is_in_list(lst: list[dict[str, str]], name: str, path: str) -> bool:
        n = (name or "").lower()
        p = (path or "").lower()
        return any(e.get("name") == n and e.get("path") == p for e in lst)

    def add_to_blocklist(self, name: str, path: str) -> None:
        with self.allow_block_lock:
            entry = self.normalize_entry(name, path)
            if not self.is_in_list(self.block_list, entry["name"], entry["path"]):
                self.block_list.append(entry)
        self.save_lists()
        self.record_event("blocklist", f"Added to block list: {name} ({path})", "warn", tags=["blocklist"])

    def add_to_allowlist(self, name: str, path: str) -> None:
        with self.allow_block_lock:
            entry = self.normalize_entry(name, path)
            if not self.is_in_list(self.allow_list, entry["name"], entry["path"]):
                self.allow_list.append(entry)
        self.save_lists()
        self.record_event("allowlist", f"Added to allow list: {name} ({path})", "info", tags=["allowlist"])

    def remove_from_blocklist(self, entry: dict[str, str]) -> None:
        with self.allow_block_lock:
            self.block_list[:] = [
                e for e in self.block_list if not (e["name"] == entry["name"] and e["path"] == entry["path"])
            ]
        self.save_lists()

    def remove_from_allowlist(self, entry: dict[str, str]) -> None:
        with self.allow_block_lock:
            self.allow_list[:] = [
                e for e in self.allow_list if not (e["name"] == entry["name"] and e["path"] == entry["path"])
            ]
        self.save_lists()

    def is_allowed(self, name: str, path: str) -> bool:
        with self.allow_block_lock:
            return self.is_in_list(self.allow_list, name, path)

    def is_blocked(self, name: str, path: str) -> bool:
        with self.allow_block_lock:
            return self.is_in_list(self.block_list, name, path)

    # --- UI Construction ---
    def _build_ui(self) -> None:
        top_frame = tk.Frame(self.root, padx=10, pady=8)
        top_frame.pack(fill=tk.X)

        tk.Label(top_frame, text="Target name/cmdline filters (comma-separated):").pack(anchor=tk.W)
        self.filter_entry = tk.Entry(top_frame)
        self.filter_entry.insert(0, ", ".join(DEFAULT_PATTERNS))
        self.filter_entry.pack(fill=tk.X, pady=(2, 6))

        tk.Label(top_frame, text="Safe / Allowlist filters (skipped unless exact target override):").pack(anchor=tk.W)
        self.allow_entry = tk.Entry(top_frame)
        self.allow_entry.insert(0, ", ".join(DEFAULT_ALLOWLIST_PATTERNS))
        self.allow_entry.pack(fill=tk.X, pady=(2, 6))

        # --- Action Row 1: Guard & Kill Switch ---
        btn_frame = tk.Frame(top_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 6))

        tk.Button(btn_frame, text="Scan & Reason", command=self.scan_processes).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Inspect Top Disk & Net", command=self.inspect_system_activity).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        tk.Button(
            btn_frame,
            text="STOP IN TRACKS (SIGTERM -> SIGKILL)",
            bg="#b91c1c",
            fg="white",
            font=("TkDefaultFont", 10, "bold"),
            command=self.stop_targets,
        ).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(
            btn_frame,
            text="Stop Highest Risk Only",
            bg="#991b1b",
            fg="white",
            command=self.stop_highest_risk_target,
        ).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Reinforce Safe", command=self.reinforce_safe_feedback).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        tk.Button(btn_frame, text="Save Snapshot", command=self.save_snapshot).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Reset Weights", command=self.reset_weights).pack(side=tk.LEFT)

        # --- Action Row 2: Glyph / Chameleon / Mirror / Shredder ---
        codec_frame = tk.LabelFrame(top_frame, text="Glyph / Chameleon / Mirror / Shredder Suite", padx=8, pady=6)
        codec_frame.pack(fill=tk.X, pady=(0, 6))

        row_in = tk.Frame(codec_frame)
        row_in.pack(fill=tk.X, pady=(0, 4))

        tk.Label(row_in, text="Phone:").pack(side=tk.LEFT)
        self.phone_entry = tk.Entry(row_in, width=16)
        self.phone_entry.insert(0, "555-019-2834")
        self.phone_entry.pack(side=tk.LEFT, padx=(2, 8))

        tk.Label(row_in, text="Biometric ID:").pack(side=tk.LEFT)
        self.bio_entry = tk.Entry(row_in, width=18)
        self.bio_entry.insert(0, "BIO-SCAN-SAMPLE-01")
        self.bio_entry.pack(side=tk.LEFT, padx=(2, 8))

        tk.Label(row_in, text="Custom Text:").pack(side=tk.LEFT)
        self.secret_entry = tk.Entry(row_in, width=28)
        self.secret_entry.insert(0, "Lab identity & machine profile")
        self.secret_entry.pack(side=tk.LEFT, padx=(2, 8))

        row_btns = tk.Frame(codec_frame)
        row_btns.pack(fill=tk.X)

        tk.Button(row_btns, text="Protect Bundle (Glyph+Mirror+Chameleon)", command=self.run_protect_bundle).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        tk.Button(row_btns, text="Rotate Chameleon Identity", command=self.rotate_chameleon).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        tk.Button(row_btns, text="Inspect Machine IDs & Telemetry", command=self.show_machine_ids).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        tk.Button(
            row_btns,
            text="Shred File...",
            bg="#7c2d12",
            fg="white",
            command=self.shred_selected_file,
        ).pack(side=tk.LEFT)

        # --- Checkboxes Row 1 ---
        opt_frame = tk.Frame(top_frame)
        opt_frame.pack(fill=tk.X, pady=(2, 4))

        self.auto_watch_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frame, text="Auto-Watch", variable=self.auto_watch_var, command=self.toggle_auto_watch).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.dry_run_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt_frame, text="Dry-Run", variable=self.dry_run_var).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_stop_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frame, text="Auto-Stop High Risk", variable=self.auto_stop_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.idle_only_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt_frame, text="Auto-Stop Only When Idle", variable=self.idle_only_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.local_op_gate_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt_frame, text="Require Local Operator for Changes", variable=self.local_op_gate_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self.audit_log_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt_frame, text="JSONL Audit Log", variable=self.audit_log_var).pack(side=tk.LEFT)

        # --- Checkboxes & Thresholds Row 2 ---
        opt2_frame = tk.Frame(top_frame)
        opt2_frame.pack(fill=tk.X, pady=(2, 4))

        tk.Label(opt2_frame, text="Poll (s):").pack(side=tk.LEFT)
        self.interval_entry = tk.Entry(opt2_frame, width=5)
        self.interval_entry.insert(0, "2.0")
        self.interval_entry.pack(side=tk.LEFT, padx=(2, 10))

        tk.Label(opt2_frame, text="Idle thresh (s):").pack(side=tk.LEFT)
        self.idle_thresh_entry = tk.Entry(opt2_frame, width=5)
        self.idle_thresh_entry.insert(0, "15.0")
        self.idle_thresh_entry.pack(side=tk.LEFT, padx=(2, 10))

        tk.Label(opt2_frame, text="Stop thresh:").pack(side=tk.LEFT)
        self.stop_thresh_entry = tk.Entry(opt2_frame, width=5)
        self.stop_thresh_entry.insert(0, f"{self.weights.get('auto_stop_threshold', 0.85):.2f}")
        self.stop_thresh_entry.pack(side=tk.LEFT, padx=(2, 12))

        self.cot_verbose_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opt2_frame, text="Show Hypothesis & Forecast CoT Trace", variable=self.cot_verbose_var).pack(
            side=tk.LEFT
        )

        # --- Readout Labels ---
        self.weights_label = tk.Label(
            top_frame, text=self.format_weights_text(), fg="#1e3a8a", anchor=tk.W, justify=tk.LEFT
        )
        self.weights_label.pack(fill=tk.X, pady=(4, 0))

        self.regime_label = tk.Label(
            top_frame,
            text="Regime: CALM | Flow: 0.00 | Pressure: 0.00 (dP=+0.00) | Queen Consensus (>1.5): {}",
            fg="#0f766e",
            anchor=tk.W,
            justify=tk.LEFT,
        )
        self.regime_label.pack(fill=tk.X, pady=(2, 0))

        # --- Console Log ---
        self.log_box = scrolledtext.ScrolledText(self.root, height=26, state=tk.DISABLED, padx=8, pady=8)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    # --- Logging, Audit & Watchdog ---
    def log(self, message: str) -> None:
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def update_log(self) -> None:
        self.log_box.update_idletasks()

    def watchdog_touch(self, name: str) -> None:
        self.watchdog_ts[name] = time.time()

    def record_event(
        self,
        category: str,
        message: str,
        severity: str = "info",
        tags: list[str] | None = None,
        meta: dict | None = None,
    ) -> None:
        tag_str = f" {tags}" if tags else ""
        self.log(f"[{severity.upper()}][{category}]{tag_str} {message}")
        self.append_audit(
            "guard_event",
            {
                "category": category,
                "severity": severity,
                "message": message,
                "tags": tags or [],
                "meta": meta or {},
            },
        )

    def guardian_log_event(self, category: str, message: str, severity: str = "info") -> None:
        self.record_event(category, message, severity=severity)

    def append_audit(self, event_type: str, payload: dict) -> None:
        if not self.audit_log_var.get():
            return
        record = {
            "ts": time.time(),
            "idle_sec": round(self.get_idle_seconds(), 2),
            "local_operator": self.is_local_operator_active(),
            "regime": self.flow_engine.regime,
            "chameleon_id": self.active_chameleon_token,
            "event": event_type,
            **payload,
        }
        try:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    # --- Local Operator & Activity Tracking ---
    def _mark_user_active(self, _event=None) -> None:
        self.last_activity_ts = time.time()

    def get_idle_seconds(self) -> float:
        return max(0.0, time.time() - self.last_activity_ts)

    def is_local_operator_active(self) -> bool:
        if not self.local_op_gate_var.get():
            return True
        return self.get_idle_seconds() <= self.get_idle_threshold()

    def get_idle_threshold(self) -> float:
        try:
            return max(1.0, float(self.idle_thresh_entry.get().strip()))
        except ValueError:
            return 15.0

    def get_stop_threshold(self) -> float:
        try:
            val = float(self.stop_thresh_entry.get().strip())
            clamped = max(0.10, min(1.0, val))
            self.weights["auto_stop_threshold"] = round(clamped, 3)
            return clamped
        except ValueError:
            return float(self.weights.get("auto_stop_threshold", 0.85))

    def is_system_idle(self) -> bool:
        return self.get_idle_seconds() >= self.get_idle_threshold()

    # --- Codec & Shredder Actions ---
    def rotate_chameleon(self) -> None:
        self.active_chameleon_token = synthesize_phantom()
        self.record_event("chameleon", f"Rotated active chameleon token -> {self.active_chameleon_token}", "info")

    def show_machine_ids(self) -> None:
        mac = get_real_mac()
        local_ip, public_ip = get_real_ip()
        os_info, machine_fp = get_telemetry()
        swarm_id = get_swarm_id()
        masked_mac = chameleon_mask(mac, "mac")
        glyph_mac = glyph_encode(reverse_and_mirror_text(mac))
        self.record_event(
            "identifiers",
            f"Swarm={swarm_id} | LocalIP={local_ip} | PublicIP={public_ip} | OS={os_info} | FP={machine_fp} | "
            f"MaskedMAC={masked_mac} | GlyphMAC={glyph_mac}",
            "info",
        )

    def run_protect_bundle(self) -> None:
        phone = self.phone_entry.get().strip()
        bio = self.bio_entry.get().strip()
        custom = self.secret_entry.get().strip()
        mac = get_real_mac()
        _os_info, fp = get_telemetry()

        protected = protect_sensitive_bundle(phone, bio, mac, fp)
        custom_flipped = reverse_and_mirror_text(custom)
        custom_glyphs = glyph_encode(custom_flipped)
        decoded_check = unmirror_and_reverse_text(glyph_decode(custom_glyphs))

        self.log("=== Protected Data Bundle (Glyph + Mirror/Flip + Chameleon) ===")
        for k, v in protected.items():
            self.log(f"  [{k}] alias={v['chameleon_alias']} | flip={v['flipped_mirror']} | glyph={v['glyph_stream']}")
        self.log(f"  [custom] flip={custom_flipped} | glyph={custom_glyphs} | roundtrip_ok={decoded_check == custom}")
        self.append_audit("protect_bundle", {"aliases": {k: v["chameleon_alias"] for k, v in protected.items()}})

    def shred_selected_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to securely shred", initialdir=BASE_DIR)
        if not path:
            return
        confirm = messagebox.askyesno(
            "Confirm Secure Shred",
            f"Overwrite and permanently delete this file?\n\n{path}",
        )
        if not confirm:
            self.log("Shred cancelled by user.")
            return
        ok, msg = shred_file(path, passes=3)
        self.record_event("shredder", msg, "warn" if ok else "crit", tags=["shred"])

    # --- Weights & Snapshot ---
    def load_weights(self) -> dict[str, float]:
        weights = dict(DEFAULT_WEIGHTS)
        if os.path.exists(WEIGHTS_FILE):
            try:
                with open(WEIGHTS_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                for k in DEFAULT_WEIGHTS:
                    if k in loaded and isinstance(loaded[k], (int, float)):
                        weights[k] = float(loaded[k])
            except Exception:
                pass
        return weights

    def save_weights(self) -> None:
        try:
            with open(WEIGHTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.weights, f, indent=2)
        except Exception as exc:
            self.log(f"Warning: could not save weights: {exc}")

    def reset_weights(self) -> None:
        self.weights = dict(DEFAULT_WEIGHTS)
        self.stop_thresh_entry.delete(0, tk.END)
        self.stop_thresh_entry.insert(0, f"{self.weights['auto_stop_threshold']:.2f}")
        self.save_weights()
        self.weights_label.config(text=self.format_weights_text())
        self.log("Weights reset to defaults.")
        self.append_audit("weights_reset", {"weights": self.weights})

    def format_weights_text(self) -> str:
        w = self.weights
        return (
            f"Weights -> pat:{w['pattern_match']:.2f} | cpu:{w['cpu_spike']:.2f} | "
            f"mem:{w['mem_growth']:.2f} | spw:{w['spawn_velocity']:.2f} | "
            f"disk:{w['disk_io']:.2f} | net:{w['net_activity']:.2f} | "
            f"chain:{w['chain_consensus']:.2f} | auto-stop >={w['auto_stop_threshold']:.2f}"
        )

    def save_snapshot(self) -> None:
        snap = {
            "ts": time.time(),
            "idle_sec": round(self.get_idle_seconds(), 2),
            "local_operator": self.is_local_operator_active(),
            "regime": self.flow_engine.regime,
            "flow_rate": round(self.flow_engine.flow_rate, 4),
            "pressure": round(self.flow_engine.pressure, 4),
            "chains": self.chain.detect(),
            "queen_consensus": self.queen.global_risk(threshold=1.5),
            "weights": self.weights,
            "beliefs": {k: {"mean": round(v.mean, 4), "var": round(v.var, 6)} for k, v in self.belief_fields.items()},
            "targets": [
                {
                    "pid": t["pid"],
                    "name": t["name"],
                    "score": t["score"],
                    "best_guess": t["best_guess"],
                    "proj_60s": t["proj_60s"],
                    "features": t["features"],
                }
                for t in self.last_scan_results
            ],
        }
        try:
            with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
                json.dump(snap, f, indent=2)
            self.log(f"Saved diagnostic snapshot to {SNAPSHOT_FILE}")
            self.append_audit("snapshot_saved", {"file": SNAPSHOT_FILE, "target_count": len(snap["targets"])})
        except Exception as exc:
            self.log(f"Warning: could not save snapshot: {exc}")

    # --- EventBus & Telemetry Ingestion ---
    def _on_bus_event(self, evt: SecEvent) -> None:
        self.chain.ingest(evt)

    def _schedule_bus_pump(self) -> None:
        self.bus.drain(max_items=200)
        self.bus_job = self.root.after(100, self._schedule_bus_pump)

    def _get_belief_field(self, key: str) -> ProbabilisticField:
        if key not in self.belief_fields:
            self.belief_fields[key] = ProbabilisticField(mean=0.25, var=0.15)
        return self.belief_fields[key]

    def ingest_telemetry_event(self, event: dict) -> None:
        try:
            opcode = (event.get("EventName") or "").lower()
            if "process" in opcode:
                image = (event.get("ImageFileName") or "").lower()
                cmd = event.get("CommandLine") or ""
                if image:
                    field = self._get_belief_field(image)
                    best_guess = field.update(0.40, weight=0.8)
                    self.bus.publish(SecEvent("proc_start", image, {"cmd": cmd, "best_guess": best_guess}))
                    self.chain.add_event("proc_spawn", {"name": image, "cmd": cmd}, entity=image)
                    if "powershell" in image or "powershell" in cmd.lower():
                        self.bus.publish(SecEvent("powershell", image, {"cmd": cmd}))

            if "connect" in opcode:
                ip = event.get("daddr") or event.get("DestIp")
                if ip:
                    field = self._get_belief_field(str(ip))
                    best_guess = field.update(0.50, weight=0.9)
                    self.bus.publish(SecEvent("net_conn", str(ip), {"best_guess": best_guess}))
                    self.chain.add_event("net_connect", {"ip": str(ip)}, entity=str(ip))

            if "file" in opcode or "write" in opcode:
                path = event.get("FileName") or event.get("path") or ""
                if path:
                    self.bus.publish(SecEvent("file_mod", str(path), {}))
        except Exception as exc:
            self.record_event("etw", f"callback error: {exc}", severity="crit")

    # --- Process & Policy Enforcement ---
    @staticmethod
    def is_windows_system_process(proc) -> bool:
        try:
            exe = proc.exe() or ""
        except Exception:
            return False
        exe_lower = exe.lower()
        return ("\\windows\\system32\\" in exe_lower) or ("\\windows defender\\" in exe_lower)

    def terminate_proc(self, proc, reason: str, auto_block: bool | None = None) -> None:
        try:
            name = proc.name()
        except Exception:
            name = "unknown"
        try:
            pid = proc.pid
        except Exception:
            pid = -1
        try:
            exe = proc.exe()
        except Exception:
            exe = ""

        # Central safety gate: every caller, including background monitors,
        # must honor Dry-Run. Dry-Run is enabled by default on first launch.
        dry_run_control = getattr(self, "dry_run_var", None)
        try:
            dry_run_enabled = bool(dry_run_control.get()) if dry_run_control is not None else True
        except Exception:
            # Fail closed if the UI variable is unavailable or unreadable.
            dry_run_enabled = True
        if dry_run_enabled:
            self.record_event(
                "policy",
                f"[DRY-RUN] Would terminate PID {pid} ({name}) - {reason}",
                "warn",
                tags=["dry-run", "would-kill"],
            )
            return

        should_block = self.trust_config.get("auto_block_on_kill", True) if auto_block is None else auto_block
        try:
            proc.terminate()
            self.record_event("policy", f"Terminated PID {pid} ({name}) - {reason}", "crit", tags=["kill"])
            if should_block:
                self.add_to_blocklist(name, exe)
        except Exception as exc:
            self.record_event("policy", f"Failed to terminate PID {pid} ({name}) - {reason} - {exc}", "warn")

    def monitor_processes(self) -> None:
        if psutil is not None:
            local_active = self.is_local_operator_active()
            for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
                try:
                    name = proc.info.get("name") or ""
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                    exe = proc.info.get("exe") or ""
                except Exception:
                    continue

                if self.is_allowed(name, exe):
                    continue
                if self.is_blocked(name, exe):
                    self.terminate_proc(proc, "on block list", auto_block=False)
                    continue

                if self.policy.get("block_remote_control", True):
                    if REMOTE_TOOL_PATTERNS.search(name) or REMOTE_TOOL_PATTERNS.search(cmdline):
                        if not local_active:
                            self.terminate_proc(proc, "remote control tool detected without local operator")
                            continue

                if SHELL_NAMES.search(name):
                    if FIREWALL_CMD_PATTERNS.search(cmdline) and self.policy.get("block_firewall_changes", True):
                        if not self.is_windows_system_process(proc) or not local_active:
                            self.terminate_proc(proc, "firewall change attempt blocked")
                            continue
                    if SETTINGS_CMD_PATTERNS.search(cmdline) and self.policy.get("block_settings_changes", True):
                        if not self.is_windows_system_process(proc) or not local_active:
                            self.terminate_proc(proc, "settings change attempt blocked")
                            continue

        self.watchdog_touch("monitor_processes")
        self.policy_job = self.root.after(7000, self.monitor_processes)

    def monitor_network(self) -> None:
        if psutil is not None:
            try:
                conns = psutil.net_connections(kind="inet")
                for c in conns:
                    raddr = getattr(c, "raddr", None)
                    if not raddr:
                        continue
                    ip = getattr(raddr, "ip", "")
                    port = getattr(raddr, "port", 0)
                    if ip and not is_private_ip(ip):
                        self.record_event("net", f"Foreign connection: {ip}:{port}", "warn", tags=["foreign"])
                        self.bus.publish(SecEvent("net_conn", f"{ip}:{port}", {"ip": ip, "port": port}))
            except Exception as exc:
                self.record_event("net", f"Failed to read connections: {exc}", "warn")

        self.watchdog_touch("monitor_network")
        self.net_job = self.root.after(8000, self.monitor_network)

    def threat_scan_and_respond(self) -> None:
        try:
            if psutil is not None:
                try:
                    conns = psutil.net_connections(kind="inet")
                except Exception as exc:
                    self.record_event("threat_scan", f"net_connections failed: {exc}", severity="warn")
                    conns = []

                seen: set[tuple[str, int]] = set()
                for conn in conns:
                    try:
                        if conn.status == "LISTEN":
                            ip = getattr(conn.laddr, "ip", "unknown")
                            port = getattr(conn.laddr, "port", 0)
                            key = (str(ip), int(port))
                            if key in seen:
                                continue
                            seen.add(key)
                            self.record_event(
                                "port_listen",
                                f"LISTEN {ip}:{port}",
                                severity="info",
                                tags=["port"],
                            )
                    except Exception:
                        continue

                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        name = proc.info.get("name") or ""
                        pid = proc.info.get("pid")
                        exe = proc.info.get("exe") or ""
                        if self.is_allowed(name, exe):
                            continue
                        if self.is_blocked(name, exe):
                            self.terminate_proc(proc, "on block list", auto_block=False)
                            continue
                        if name and self.policy.get("block_suspicious_procs", True):
                            if SUSPICIOUS_PROC_PATTERNS.search(name):
                                self.terminate_proc(proc, f"suspicious process pattern (PID {pid})")
                    except Exception:
                        continue
        except Exception as exc:
            self.record_event("self_rewrite", f"threat_scan_and_respond() failed - {exc}", severity="crit", tags=["self_rewrite"])

        self.update_log()
        self.watchdog_touch("threat_scan")
        self.threat_job = self.root.after(10000, self.threat_scan_and_respond)

    def self_check(self) -> None:
        try:
            assert callable(self.threat_scan_and_respond)
            assert callable(self.update_log)
            assert isinstance(self.trust_config, dict)
            assert isinstance(self.policy, dict)
        except Exception as exc:
            self.record_event("self_rewrite", f"Integrity check failed - {exc}", severity="crit", tags=["self_rewrite"])
        self.watchdog_touch("self_check")
        self.self_check_job = self.root.after(15000, self.self_check)

    # --- Predictive Scoring & Scan ---
    def parse_csv(self, entry: tk.Entry) -> list[str]:
        return [item.strip().lower() for item in entry.get().split(",") if item.strip()]

    def get_interval(self) -> float:
        try:
            val = float(self.interval_entry.get().strip())
            return max(0.5, min(val, 60.0))
        except ValueError:
            return 2.0

    def toggle_auto_watch(self) -> None:
        if self.auto_watch_var.get():
            self.log("Auto-Watch enabled.")
            self.schedule_watch_tick()
        else:
            if self.watch_job is not None:
                self.root.after_cancel(self.watch_job)
                self.watch_job = None
            self.log("Auto-Watch disabled.")

    def schedule_watch_tick(self) -> None:
        if not self.auto_watch_var.get():
            return
        self.scan_processes(from_watch=True)
        delay_ms = int(self.get_interval() * 1000)
        self.watch_job = self.root.after(delay_ms, self.schedule_watch_tick)

    def _safe_io_bytes(self, proc) -> float:
        try:
            io = proc.io_counters()
            return float((io.read_bytes or 0) + (io.write_bytes or 0))
        except Exception:
            return 0.0

    def _safe_conn_count(self, proc) -> tuple[int, list[str]]:
        endpoints: list[str] = []
        try:
            conns = proc.net_connections(kind="inet")
            for c in conns[:5]:
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "local"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "none"
                endpoints.append(f"{c.status or 'SOCKET'}({laddr}->{raddr})")
            return len(conns), endpoints
        except Exception:
            return 0, endpoints

    def inspect_system_activity(self) -> None:
        if psutil is None:
            self.log("psutil not available for system I/O inspection.")
            return
        now = time.time()
        idle_sec = self.get_idle_seconds()
        idle_flag = "IDLE" if self.is_system_idle() else "ACTIVE"
        self.log(f"=== System Activity Snapshot ({idle_flag}, idle={idle_sec:.1f}s) ===")

        disk_entries: list[tuple[float, int, str]] = []
        net_entries: list[tuple[int, int, str, list[str]]] = []

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.pid
                name = (proc.info.get("name") or "unknown").lower()
                io_total = self._safe_io_bytes(proc)
                prev = self.history.get(pid)
                io_rate_kb = 0.0
                if prev and "io_bytes" in prev:
                    dt = max(0.1, now - prev["ts"])
                    io_rate_kb = max(0.0, (io_total - prev["io_bytes"]) / 1024.0 / dt)
                if io_rate_kb > 0.0:
                    disk_entries.append((io_rate_kb, pid, name))
                    if io_rate_kb > 512.0:
                        self.bus.publish(SecEvent("file_mod", name, {"pid": pid, "kb_s": round(io_rate_kb, 1)}))

                conn_cnt, eps = self._safe_conn_count(proc)
                if conn_cnt > 0:
                    net_entries.append((conn_cnt, pid, name, eps))
                    self.bus.publish(SecEvent("net_conn", name, {"pid": pid, "sockets": conn_cnt}))
            except Exception:
                continue

        self.bus.drain(max_items=200)
        disk_entries.sort(reverse=True)
        net_entries.sort(reverse=True)

        self.log("Top Disk I/O Rate (delta since last sample):")
        if not disk_entries:
            self.log("  No measurable positive disk delta yet (run again in a couple seconds).")
        for rate_kb, pid, name in disk_entries[:6]:
            self.log(f"  PID {pid} ({name}): ~{rate_kb:.1f} KB/s")

        self.log("Top Active Network Sockets:")
        if not net_entries:
            self.log("  No accessible active sockets reported.")
        for cnt, pid, name, eps in net_entries[:6]:
            preview = ", ".join(eps[:3])
            self.log(f"  PID {pid} ({name}): {cnt} socket(s) [{preview}]")

    def evaluate_process(
        self,
        proc,
        patterns: list[str],
        allowlist: list[str],
        now: float,
        idle_active: bool,
        chain_boost: float,
    ) -> dict | None:
        try:
            name = (proc.info.get("name") or "").lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            exe = (proc.info.get("exe") or "").lower()
            combined = f"{name} {cmdline}".strip()

            if self.is_allowed(name, exe):
                return None

            matched_patterns = [p for p in patterns if p in combined]
            if not matched_patterns and not self.is_blocked(name, exe):
                return None
            if not matched_patterns:
                matched_patterns = ["blocklist"]

            if any(a in name for a in allowlist) and len(matched_patterns) == 1 and not self.is_blocked(name, exe):
                return None

            cpu_pct = proc.cpu_percent(interval=None)
            rss_mb = proc.memory_info().rss / (1024 * 1024)
            child_count = len(proc.children(recursive=False))
            io_bytes = self._safe_io_bytes(proc)
            conn_count, endpoints = self._safe_conn_count(proc)

            prev = self.history.get(proc.pid)
            dt = max(0.1, now - prev["ts"]) if prev else 1.0
            cpu_delta = max(0.0, cpu_pct - prev["cpu"]) if prev else 0.0
            mem_delta_mb = max(0.0, rss_mb - prev["rss_mb"]) if prev else 0.0
            spawn_rate = max(0.0, (child_count - prev["children"]) / dt) if prev else float(child_count)
            io_rate_mb = (
                max(0.0, (io_bytes - prev["io_bytes"]) / (1024 * 1024) / dt)
                if (prev and "io_bytes" in prev)
                else 0.0
            )

            self.history[proc.pid] = {
                "ts": now,
                "cpu": cpu_pct,
                "rss_mb": rss_mb,
                "children": float(child_count),
                "io_bytes": io_bytes,
            }

            self.bus.publish(SecEvent("proc_start", name or str(proc.pid), {"pid": proc.pid, "cmdline": cmdline[:120]}))
            if "powershell" in combined:
                self.bus.publish(SecEvent("powershell", name or str(proc.pid), {"pid": proc.pid}))
            if conn_count > 0:
                self.bus.publish(SecEvent("net_conn", name or str(proc.pid), {"pid": proc.pid, "sockets": conn_count}))
            if io_rate_mb > 0.5:
                self.bus.publish(SecEvent("file_mod", name or str(proc.pid), {"pid": proc.pid, "mb_s": round(io_rate_mb, 2)}))

            sig = f"{name}:{matched_patterns[0]}"
            events = self.respawn_events.setdefault(sig, [])
            events.append(now)
            self.respawn_events[sig] = [t for t in events if now - t <= 30.0]
            respawn_burst = len(self.respawn_events[sig])

            idle_disk_multiplier = 1.35 if idle_active else 1.0

            f_pattern = min(1.0, 0.65 + 0.15 * len(matched_patterns))
            f_cpu = min(1.0, (cpu_pct + cpu_delta) / 100.0)
            f_mem = min(1.0, mem_delta_mb / 150.0)
            f_spawn = min(1.0, (spawn_rate + max(0, respawn_burst - 2) * 0.25) / 3.0)
            f_disk = min(1.0, (io_rate_mb * idle_disk_multiplier) / 25.0)
            f_net = min(1.0, conn_count / 10.0)
            f_chain = min(1.0, chain_boost)

            w = self.weights
            raw_score = (
                w["pattern_match"] * f_pattern
                + w["cpu_spike"] * f_cpu
                + w["mem_growth"] * f_mem
                + w["spawn_velocity"] * f_spawn
                + w["disk_io"] * f_disk
                + w["net_activity"] * f_net
                + w["chain_consensus"] * f_chain
            )
            predicted_risk = round(min(1.0, raw_score), 3)

            slope_signal = (
                0.15 * min(1.0, spawn_rate / 2.0)
                + 0.15 * min(1.0, io_rate_mb / 15.0)
                + 0.10 * max(0.0, min(1.0, self.flow_engine.pressure_delta))
            )
            proj_60s = round(min(1.0, predicted_risk + slope_signal), 3)

            belief = self._get_belief_field(sig)
            best_guess = round(belief.update(predicted_risk, weight=0.85), 3)

            stop_thresh = self.get_stop_threshold()
            threat_hyp = (
                f"ThreatHyp={predicted_risk:.3f} (proj60s={proj_60s:.3f}) from "
                f"pat={matched_patterns}, spw={spawn_rate:.2f}/s, io={io_rate_mb:.2f}MB/s, sock={conn_count}, chain={f_chain:.2f}"
            )
            benign_reasons = []
            if not idle_active:
                benign_reasons.append("user_active")
            if conn_count == 0:
                benign_reasons.append("no_sockets")
            if spawn_rate == 0.0 and io_rate_mb < 0.2:
                benign_reasons.append("low_delta")
            benign_hyp = f"BenignCounter=[{', '.join(benign_reasons) if benign_reasons else 'none_detected'}]"

            cot_steps = [
                f"[1] Context & Regime: matched={matched_patterns}, idle={idle_active}, regime={self.flow_engine.regime}",
                f"[2] Hypothesis Check: {threat_hyp} | {benign_hyp}",
                f"[3] Probabilistic & Consensus: best_guess={best_guess:.3f} (var={belief.var:.4f}), cpu={cpu_pct:.1f}%, mem={rss_mb:.1f}MB",
                f"[4] Action Plan: {'AUTO-STOP CANDIDATE' if proj_60s >= stop_thresh or predicted_risk >= stop_thresh else 'MONITOR / MANUAL STOP READY'}",
            ]

            return {
                "proc": proc,
                "pid": proc.pid,
                "name": name or "unknown",
                "entity": f"{name or 'proc'}:{proc.pid}",
                "sig": sig,
                "score": predicted_risk,
                "proj_60s": proj_60s,
                "best_guess": best_guess,
                "sockets": endpoints,
                "features": {
                    "pattern": f_pattern,
                    "cpu": f_cpu,
                    "mem": f_mem,
                    "spawn": f_spawn,
                    "disk": f_disk,
                    "net": f_net,
                    "chain": f_chain,
                },
                "cot_steps": cot_steps,
            }
        except Exception:
            return None

    def _cleanup_stale_pids(self, active_pids: set[int]) -> None:
        stale = [pid for pid in self.history if pid not in active_pids]
        for pid in stale:
            del self.history[pid]

    def find_evaluated_matches(self) -> list[dict]:
        self.bus.drain(max_items=200)
        if psutil is None:
            return []

        patterns = self.parse_csv(self.filter_entry)
        allowlist = self.parse_csv(self.allow_entry)
        if not patterns and not self.block_list:
            return []

        now = time.time()
        idle_active = self.is_system_idle()
        current_pid = psutil.Process().pid

        active_chains = self.chain.detect()
        chain_boost = max((sc for _cname, sc in active_chains), default=0.0)

        results: list[dict] = []
        seen_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            seen_pids.add(proc.pid)
            if proc.pid == current_pid:
                continue
            item = self.evaluate_process(proc, patterns, allowlist, now, idle_active, chain_boost)
            if item is not None:
                results.append(item)

        self._cleanup_stale_pids(seen_pids)
        self.bus.drain(max_items=200)

        self.queen.update(
            "process_guard",
            [{"entity": r["entity"], "score": r["score"]} for r in results],
        )
        self.queen.update(
            "chain_engine",
            [{"entity": r["entity"], "score": r["features"]["chain"] * 1.2} for r in results if r["features"]["chain"] > 0],
        )

        recent_rate = len(self.chain.events) / max(1.0, self.chain.window)
        max_risk = max((r["score"] for r in results), default=0.0)
        self.flow_engine.step(recent_rate, max_risk, len(active_chains))

        consensus_high = self.queen.global_risk(threshold=1.5)
        self.regime_label.config(
            text=(
                f"Regime: {self.flow_engine.regime} | Flow: {self.flow_engine.flow_rate:.2f} | "
                f"Pressure: {self.flow_engine.pressure:.2f} (dP={self.flow_engine.pressure_delta:+.2f}) | "
                f"Queen Consensus (>1.5): {consensus_high}"
            )
        )

        results.sort(key=lambda x: (x["score"], x["proj_60s"]), reverse=True)
        self.last_scan_results = results
        return results

    def scan_processes(self, from_watch: bool = False) -> None:
        matches = self.find_evaluated_matches()
        chains = self.chain.detect()
        prefix = "[WATCH]" if from_watch else "[SCAN]"
        idle_tag = "IDLE" if self.is_system_idle() else "ACTIVE"
        self.log(
            f"{prefix} ({idle_tag}, idle={self.get_idle_seconds():.1f}s, regime={self.flow_engine.regime}) "
            f"Found {len(matches)} target process(es) | Chains={chains}"
        )

        for item in matches:
            self.log(
                f"  -> PID {item['pid']} ({item['name']}) | Risk={item['score']:.3f} | "
                f"Proj60s={item['proj_60s']:.3f} | BestGuess={item['best_guess']:.3f}"
            )
            if self.cot_verbose_var.get():
                for step in item["cot_steps"]:
                    self.log(f"       {step}")
            if item["sockets"]:
                self.log(f"       Sockets: {', '.join(item['sockets'][:3])}")

        self.append_audit(
            "scan",
            {
                "count": len(matches),
                "chains": chains,
                "flow_rate": round(self.flow_engine.flow_rate, 3),
                "pressure": round(self.flow_engine.pressure, 3),
                "targets": [
                    {
                        "pid": m["pid"],
                        "name": m["name"],
                        "score": m["score"],
                        "proj_60s": m["proj_60s"],
                        "best_guess": m["best_guess"],
                        "features": m["features"],
                    }
                    for m in matches
                ],
            },
        )

        if self.auto_stop_var.get() and matches:
            if self.idle_only_var.get() and not self.is_system_idle():
                self.log("[AUTO-STOP] Skipped because system is not idle.")
                return
            threshold = self.get_stop_threshold()
            high_risk = [m for m in matches if m["score"] >= threshold or m["proj_60s"] >= threshold]
            if high_risk:
                self.log(f"[AUTO-STOP] {len(high_risk)} process(es) crossed threshold {threshold:.2f}.")
                self._execute_stop(high_risk, trigger="auto_stop")

    def reinforce_safe_feedback(self) -> None:
        for key in ("cpu_spike", "mem_growth", "spawn_velocity", "disk_io", "net_activity", "chain_consensus"):
            self.weights[key] = max(0.05, round(self.weights[key] * 0.92, 4))
        self.weights["pattern_match"] = max(0.15, round(self.weights["pattern_match"] * 0.97, 4))
        for item in self.last_scan_results:
            self._get_belief_field(item["sig"]).update(0.10, weight=0.7)
        self.save_weights()
        self.weights_label.config(text=self.format_weights_text())
        self.log("Feedback recorded: dampened weights and Bayesian best-guess priors for seen targets.")
        self.append_audit("reinforce_safe", {"weights": self.weights})

    def _learn_from_confirmed_stop(self, targets: list[dict]) -> None:
        if not targets:
            return
        feature_to_weight = {
            "pattern": ("pattern_match", 0.50),
            "cpu": ("cpu_spike", 0.30),
            "mem": ("mem_growth", 0.30),
            "spawn": ("spawn_velocity", 0.30),
            "disk": ("disk_io", 0.25),
            "net": ("net_activity", 0.25),
            "chain": ("chain_consensus", 0.25),
        }
        step = 0.025
        for f_key, (w_key, baseline) in feature_to_weight.items():
            avg_val = sum(t["features"].get(f_key, 0.0) for t in targets) / len(targets)
            floor = 0.15 if w_key == "pattern_match" else 0.05
            self.weights[w_key] = max(floor, round(self.weights[w_key] + step * (avg_val - baseline), 4))

        for t in targets:
            self._get_belief_field(t["sig"]).update(0.90, weight=1.0)

        self.save_weights()
        self.weights_label.config(text=self.format_weights_text())

    def stop_highest_risk_target(self) -> None:
        matches = self.find_evaluated_matches()
        if not matches:
            self.log("No matching processes running.")
            return
        top_target = [matches[0]]
        if not self.dry_run_var.get():
            confirm = messagebox.askyesno(
                "Confirm Highest-Risk Stop",
                f"Terminate highest-risk target PID {top_target[0]['pid']} ({top_target[0]['name']}) "
                f"[Risk={top_target[0]['score']:.3f}] and its children now?",
            )
            if not confirm:
                self.log("Highest-risk stop cancelled by user.")
                return
        self._execute_stop(top_target, trigger="manual_top_stop")

    def stop_targets(self) -> None:
        matches = self.find_evaluated_matches()
        if not matches:
            self.log("No matching processes running.")
            return

        if not self.dry_run_var.get():
            confirm = messagebox.askyesno(
                "Confirm Stop",
                f"Terminate {len(matches)} matching process(es) and their child trees now?",
            )
            if not confirm:
                self.log("Stop cancelled by user.")
                return

        self._execute_stop(matches, trigger="manual_stop")

    def _execute_stop(self, matches: list[dict], trigger: str = "manual_stop") -> None:
        victims = []
        seen_pids: set[int] = set()

        for item in matches:
            p = item["proc"]
            try:
                tree = [p] + p.children(recursive=True)
            except Exception:
                tree = [p]

            for member in tree:
                if member.pid not in seen_pids:
                    seen_pids.add(member.pid)
                    victims.append(member)

        if self.dry_run_var.get():
            self.log(f"[DRY-RUN] Would terminate {len(victims)} process(es) (including children):")
            for member in victims:
                try:
                    self.log(f"  - PID {member.pid} ({member.name()})")
                except Exception:
                    self.log(f"  - PID {member.pid}")
            self.append_audit("dry_run_stop", {"trigger": trigger, "victim_pids": [m.pid for m in victims]})
            return

        stopped_pids: list[int] = []
        for member in victims:
            try:
                member.terminate()
                stopped_pids.append(member.pid)
                self.log(f"Sent SIGTERM to PID {member.pid} ({member.name()})")
            except Exception as exc:
                self.log(f"Could not terminate PID {member.pid}: {exc}")

        if psutil is not None:
            _, alive = psutil.wait_procs(victims, timeout=3)
            for member in alive:
                try:
                    member.kill()
                    self.log(f"Force-killed (SIGKILL) PID {member.pid}")
                except Exception as exc:
                    self.log(f"Could not force-kill PID {member.pid}: {exc}")

        self._learn_from_confirmed_stop(matches)
        self.log("Updated learning weights and Bayesian best-guess beliefs from confirmed stop.")
        self.append_audit(
            "confirmed_stop",
            {
                "trigger": trigger,
                "matched_pids": [m["pid"] for m in matches],
                "victim_pids": stopped_pids,
                "weights": self.weights,
            },
        )
        self.scan_processes()


if __name__ == "__main__":
    root = tk.Tk()
    app = AutonomousGuardianGUI(root)
    root.mainloop()