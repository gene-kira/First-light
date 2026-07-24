#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Purge Shell – Unified Python File v4
Fake Telemetry + Persona Engine + IdentityCRL Shadow Layer

Upgrades:
- Kill Switch (force-block identity even if shadow OFF)
- Auto-Kill mode (Kill Switch auto-activates on leak detection)
- Leak Detector (alerts on real LID usage risk)
- Identity Flooder (floods subsystems with fake identity to confuse telemetry)
- Stealth Mode (machine appears “identity-null”)
- Persona Lock (freeze fake identity)
- Persona Swarm (multiple fake identities rotating in patterns)
- Glyph-coded warning system in GUI
- First-Boot Integrity Check
- Reboot-Safe Persona Rotation
- Cold-Boot Stealth Mode Auto-Enable
- Reboot-Lockdown Timer

All behavior is safe and simulated (no destructive OS changes).
"""

import json
import time
import threading
import random
import queue
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk = None
    ttk = None


# ============================================================
# Core Utilities
# ============================================================

class SafeLogger:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries: List[str] = []

    def log(self, msg: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{ts}] {msg}"
        with self._lock:
            self._entries.append(line)
        print(line)

    def get_recent(self, limit: int = 200) -> List[str]:
        with self._lock:
            return self._entries[-limit:]


class JsonStateStore:
    """
    Simple JSON persistence for persona + identity shadow state + boot metadata.
    """
    def __init__(self, path: str, logger: SafeLogger):
        self.path = path
        self.logger = logger
        self.state: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.state = json.load(f)
            self.logger.log(f"State loaded from {self.path}")
        except FileNotFoundError:
            self.logger.log(f"No existing state file at {self.path}, starting fresh.")
            self.state = {}
        except Exception as e:
            self.logger.log(f"Error loading state: {e}")
            self.state = {}

    def save(self):
        with self._lock:
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.state, f, indent=2)
                self.logger.log(f"State saved to {self.path}")
            except Exception as e:
                self.logger.log(f"Error saving state: {e}")

    def get(self, key: str, default=None):
        with self._lock:
            return self.state.get(key, default)

    def set(self, key: str, value: Any):
        with self._lock:
            self.state[key] = value
        self.save()


# ============================================================
# Boot Metadata / Integrity Check
# ============================================================

@dataclass
class BootInfo:
    first_boot: bool
    last_boot_ts: float
    current_boot_ts: float
    reboot_interval_sec: float


def compute_boot_info(state_store: JsonStateStore, logger: SafeLogger) -> BootInfo:
    current_ts = time.time()
    last_boot_ts = state_store.get("last_boot_ts", 0.0)
    first_boot_done = bool(state_store.get("first_boot_done", False))

    first_boot = not first_boot_done
    reboot_interval = current_ts - last_boot_ts if last_boot_ts > 0 else 0.0

    # First-Boot Integrity Check
    if first_boot:
        logger.log("[IntegrityCheck] First boot detected. Validating state structure.")
        # Simple structural checks
        for key in ["persona", "identity_shadow"]:
            if key not in state_store.state:
                logger.log(f"[IntegrityCheck] Missing key '{key}' in state. This is expected on first boot.")
        state_store.set("first_boot_done", True)
    else:
        logger.log(f"[IntegrityCheck] Subsequent boot detected. Reboot interval ~{int(reboot_interval)}s.")

    state_store.set("last_boot_ts", current_ts)

    return BootInfo(
        first_boot=first_boot,
        last_boot_ts=last_boot_ts,
        current_boot_ts=current_ts,
        reboot_interval_sec=reboot_interval,
    )


# ============================================================
# Persona Engine (Persona Lock + Persona Swarm + Reboot-Safe Rotation)
# ============================================================

@dataclass
class FakePersona:
    id: str
    device_fingerprint: str
    activity_profile: str
    sync_state: str
    risk_level: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class PersonaEngine:
    """
    Generates and manages fake personas used by the Fake Telemetry Engine.
    Supports:
    - Persona Lock (freeze identity)
    - Persona Swarm (multiple personas rotating in patterns)
    - Reboot-Safe Persona Rotation
    """
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()

        self.current_persona: Optional[FakePersona] = None
        self.persona_locked: bool = False

        self.swarm_enabled: bool = False
        self.swarm_personas: List[FakePersona] = []
        self.swarm_index: int = 0

        self._load_or_create_persona()
        self._load_lock_state()
        self._load_swarm_state()

    def _load_or_create_persona(self):
        data = self.state_store.get("persona", None)
        if data:
            self.current_persona = FakePersona(**data)
            self.logger.log("Loaded existing fake persona from state.")
        else:
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.logger.log("Generated new fake persona.")

    def _load_lock_state(self):
        locked = self.state_store.get("persona_locked", False)
        self.persona_locked = bool(locked)
        self.logger.log(f"Persona lock state loaded: locked={self.persona_locked}")

    def _load_swarm_state(self):
        swarm_data = self.state_store.get("persona_swarm", None)
        self.swarm_enabled = bool(self.state_store.get("swarm_enabled", False))
        if swarm_data:
            try:
                self.swarm_personas = [FakePersona(**p) for p in swarm_data]
                self.logger.log(f"Loaded Persona Swarm with {len(self.swarm_personas)} personas.")
            except Exception as e:
                self.logger.log(f"Error loading Persona Swarm: {e}")
                self.swarm_personas = []
        else:
            self.swarm_personas = []

    def _persist_persona(self):
        if self.current_persona:
            self.state_store.set("persona", self.current_persona.__dict__)

    def _persist_lock_state(self):
        self.state_store.set("persona_locked", self.persona_locked)

    def _persist_swarm_state(self):
        swarm_data = [p.__dict__ for p in self.swarm_personas]
        self.state_store.set("persona_swarm", swarm_data)
        self.state_store.set("swarm_enabled", self.swarm_enabled)

    def _generate_new_persona(self) -> FakePersona:
        pid = f"persona-{random.randint(10**8, 10**9-1)}"
        fingerprint = f"FP-{random.randint(10**12, 10**13-1)}"
        activity = random.choice(["light", "moderate", "heavy"])
        sync_state = random.choice(["in-sync", "lagging", "desynced"])
        risk = random.choice(["low", "medium", "high"])
        metadata = {
            "os_profile": "Windows-Shadow",
            "region": random.choice(["US", "EU", "APAC"]),
            "role": random.choice(["workstation", "lab-node", "honeypot"]),
        }
        return FakePersona(
            id=pid,
            device_fingerprint=fingerprint,
            activity_profile=activity,
            sync_state=sync_state,
            risk_level=risk,
            metadata=metadata,
        )

    def rotate_persona(self):
        with self._lock:
            if self.persona_locked:
                self.logger.log("Persona rotation requested but Persona Lock is ACTIVE. Rotation skipped.")
                return
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.logger.log("Persona rotated.")

    def get_persona(self, subsystem: str = "") -> FakePersona:
        with self._lock:
            if self.swarm_enabled and self.swarm_personas:
                self.swarm_index = (self.swarm_index + 1) % len(self.swarm_personas)
                persona = self.swarm_personas[self.swarm_index]
                self.logger.log(
                    f"Persona Swarm selected persona [{persona.id}] for subsystem [{subsystem}]."
                )
                return persona
            return self.current_persona

    def toggle_lock(self):
        with self._lock:
            self.persona_locked = not self.persona_locked
            self._persist_lock_state()
            state = "ACTIVE" if self.persona_locked else "INACTIVE"
            self.logger.log(f"Persona Lock toggled: {state}")

    def get_lock_state(self) -> bool:
        with self._lock:
            return self.persona_locked

    def toggle_swarm(self):
        with self._lock:
            self.swarm_enabled = not self.swarm_enabled
            if self.swarm_enabled and not self.swarm_personas:
                self.swarm_personas = [self._generate_new_persona() for _ in range(3)]
                self.logger.log("Persona Swarm initialized with 3 personas.")
            self._persist_swarm_state()
            state = "ACTIVE" if self.swarm_enabled else "INACTIVE"
            self.logger.log(f"Persona Swarm toggled: {state}")

    def get_swarm_state(self) -> bool:
        with self._lock:
            return self.swarm_enabled

    def get_swarm_snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.__dict__ for p in self.swarm_personas]

    def apply_boot_policies(self, boot_info: BootInfo):
        """
        Reboot-Safe Persona Rotation:
        - On first boot: keep persona but log.
        - On subsequent boots: optionally rotate persona if not locked.
        """
        with self._lock:
            if boot_info.first_boot:
                self.logger.log("[BootPolicy] First boot: Persona kept as-is.")
            else:
                if not self.persona_locked:
                    self.logger.log("[BootPolicy] Reboot detected: rotating persona safely.")
                    self.current_persona = self._generate_new_persona()
                    self._persist_persona()
                else:
                    self.logger.log("[BootPolicy] Reboot detected but Persona Lock ACTIVE; rotation skipped.")


# ============================================================
# IdentityCRL Shadow Layer (Kill Switch + Auto-Kill + Stealth + Leak Detector + Reboot Lockdown)
# ============================================================

@dataclass
class IdentityShadowState:
    real_lid_hex: Optional[str] = None
    real_lid_numeric: Optional[int] = None
    fake_lid_numeric: Optional[int] = None
    active: bool = False
    last_rotation_ts: float = 0.0
    kill_switch: bool = False
    auto_kill: bool = False
    stealth_mode: bool = False
    reboot_lockdown_until: float = 0.0  # timestamp until which lockdown is active


class IdentityShadowLayer:
    """
    Safe, non-destructive IdentityCRL shadow layer.
    - Reads real LID (stubbed).
    - Generates fake LID.
    - Provides fake identity when active or Kill Switch is ON.
    - Auto-Kill: activates Kill Switch on leak detection.
    - Stealth Mode: returns identity-null (0) and logs stealth.
    - Leak Detector: warns when real LID would be used.
    - Reboot-Lockdown Timer: temporary kill-switch window after reboot.
    """
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self.state = IdentityShadowState()
        self._lock = threading.Lock()
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("identity_shadow", None)
        if data:
            self.state = IdentityShadowState(**data)
            self.logger.log("Loaded Identity Shadow state from JSON.")
        else:
            self.logger.log("No Identity Shadow state found; initializing fresh.")
            self._init_state()
            self._persist_state()

    def _init_state(self):
        self.state.real_lid_hex = f"{random.getrandbits(64):016x}"
        self.state.real_lid_numeric = int(self.state.real_lid_hex, 16)
        self.state.fake_lid_numeric = self._generate_fake_lid()
        self.state.active = False
        self.state.kill_switch = False
        self.state.auto_kill = False
        self.state.stealth_mode = False
        self.state.reboot_lockdown_until = 0.0
        self.state.last_rotation_ts = time.time()
        self.logger.log(
            f"Initialized Identity Shadow: real_hex={self.state.real_lid_hex}, "
            f"real_numeric={self.state.real_lid_numeric}, fake={self.state.fake_lid_numeric}"
        )

    def _persist_state(self):
        self.state_store.set("identity_shadow", self.state.__dict__)

    def _generate_fake_lid(self) -> int:
        fake = random.getrandbits(64)
        self.logger.log(f"Generated fake LID: {fake}")
        return fake

    def activate(self):
        with self._lock:
            if not self.state.active:
                self.state.active = True
                self.logger.log("Identity Shadow Layer ACTIVATED.")
                self._persist_state()

    def deactivate(self):
        with self._lock:
            if self.state.active:
                self.state.active = False
                self.logger.log("Identity Shadow Layer DEACTIVATED.")
                self._persist_state()

    def toggle_kill_switch(self):
        with self._lock:
            self.state.kill_switch = not self.state.kill_switch
            state = "ACTIVE" if self.state.kill_switch else "INACTIVE"
            self.logger.log(f"Kill Switch toggled: {state}")
            self._persist_state()

    def toggle_auto_kill(self):
        with self._lock:
            self.state.auto_kill = not self.state.auto_kill
            state = "ACTIVE" if self.state.auto_kill else "INACTIVE"
            self.logger.log(f"Auto-Kill mode toggled: {state}")
            self._persist_state()

    def toggle_stealth_mode(self):
        with self._lock:
            self.state.stealth_mode = not self.state.stealth_mode
            state = "ACTIVE" if self.state.stealth_mode else "INACTIVE"
            self.logger.log(f"Stealth Mode toggled: {state}")
            self._persist_state()

    def rotate_fake_lid(self):
        with self._lock:
            self.state.fake_lid_numeric = self._generate_fake_lid()
            self.state.last_rotation_ts = time.time()
            self.logger.log("Fake LID rotated.")
            self._persist_state()

    def apply_boot_policies(self, boot_info: BootInfo):
        """
        Cold-Boot Stealth Mode Auto-Enable + Reboot-Lockdown Timer:
        - On first boot: enable Stealth Mode.
        - On subsequent boots: set a lockdown window where Kill Switch is forced ON.
        """
        with self._lock:
            if boot_info.first_boot:
                self.state.stealth_mode = True
                self.logger.log("[BootPolicy] First boot: Stealth Mode AUTO-ENABLED.")
            else:
                lockdown_duration = 300  # 5 minutes
                self.state.reboot_lockdown_until = boot_info.current_boot_ts + lockdown_duration
                self.logger.log(
                    f"[BootPolicy] Reboot detected: Lockdown timer set for {lockdown_duration}s."
                )
            self._persist_state()

    def _lockdown_active(self) -> bool:
        return time.time() < self.state.reboot_lockdown_until

    def get_effective_lid(self, subsystem: str) -> int:
        """
        Returns the LID that should be used by higher layers.
        - If Stealth Mode is ON: identity-null (0).
        - If Kill Switch is ON or lockdown window active: always fake LID.
        - If Shadow is active: fake LID.
        - Else: real LID, but Leak Detector logs a warning and Auto-Kill may trigger.
        """
        with self._lock:
            if self.state.stealth_mode:
                self.logger.log(
                    f"[StealthMode] Subsystem {subsystem} requested identity. Identity-null returned."
                )
                return 0

            if self.state.kill_switch or self._lockdown_active():
                if self.state.fake_lid_numeric is None:
                    self.state.fake_lid_numeric = self._generate_fake_lid()
                    self._persist_state()
                if self._lockdown_active():
                    self.logger.log(
                        f"[Lockdown] Subsystem {subsystem} requested identity during reboot lockdown. Fake LID enforced."
                    )
                else:
                    self.logger.log(
                        f"[KillSwitch] Subsystem {subsystem} requested identity. Fake LID enforced."
                    )
                return self.state.fake_lid_numeric

            if self.state.active and self.state.fake_lid_numeric is not None:
                return self.state.fake_lid_numeric

            self._log_leak(subsystem)
            if self.state.auto_kill:
                self.state.kill_switch = True
                self.logger.log(
                    f"[AutoKill] Leak detected for subsystem [{subsystem}]. Kill Switch ACTIVATED."
                )
                self._persist_state()
                return self.state.fake_lid_numeric or self._generate_fake_lid()

            return self.state.real_lid_numeric or 0

    def _log_leak(self, subsystem: str):
        self.logger.log(
            f"[LeakDetector] Potential real LID usage by subsystem [{subsystem}] "
            f"(Shadow OFF, KillSwitch OFF, Stealth OFF, Lockdown OFF)."
        )

    def get_state_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "real_lid_hex": self.state.real_lid_hex,
                "real_lid_numeric": self.state.real_lid_numeric,
                "fake_lid_numeric": self.state.fake_lid_numeric,
                "active": self.state.active,
                "kill_switch": self.state.kill_switch,
                "auto_kill": self.state.auto_kill,
                "stealth_mode": self.state.stealth_mode,
                "reboot_lockdown_until": self.state.reboot_lockdown_until,
                "last_rotation_ts": self.state.last_rotation_ts,
            }


# ============================================================
# Fake Telemetry Engine (Identity Flooder + Glyphs)
# ============================================================

class FakeTelemetryEngine:
    """
    Uses PersonaEngine + IdentityShadowLayer to generate fake telemetry.
    Integrates:
    - Kill Switch
    - Auto-Kill
    - Leak Detector
    - Identity Flooder
    - Stealth Mode
    - Persona Swarm
    """
    def __init__(
        self,
        persona_engine: PersonaEngine,
        identity_shadow: IdentityShadowLayer,
        logger: SafeLogger,
    ):
        self.persona_engine = persona_engine
        self.identity_shadow = identity_shadow
        self.logger = logger
        self._lock = threading.Lock()
        self._event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.flooder_enabled: bool = False

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True)
                self._thread.start()
                self.logger.log("Fake Telemetry Engine started.")

    def stop(self):
        with self._lock:
            self._running = False
        self.logger.log("Fake Telemetry Engine stopped.")

    def _loop(self):
        while True:
            with self._lock:
                if not self._running:
                    break
            try:
                event = self._event_queue.get(timeout=0.5)
                self._process_event(event)
            except queue.Empty:
                pass

    def submit_identity_access(self, subsystem: str):
        persona = self.persona_engine.get_persona(subsystem)
        effective_lid = self.identity_shadow.get_effective_lid(subsystem)
        snapshot = self.identity_shadow.get_state_snapshot()
        event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona": persona.__dict__,
            "effective_lid": effective_lid,
            "shadow_active": snapshot["active"],
            "kill_switch": snapshot["kill_switch"],
            "auto_kill": snapshot["auto_kill"],
            "stealth_mode": snapshot["stealth_mode"],
            "lockdown_until": snapshot["reboot_lockdown_until"],
            "ts": time.time(),
        }
        self._event_queue.put(event)

    def toggle_flooder(self):
        with self._lock:
            self.flooder_enabled = not self.flooder_enabled
            state = "ACTIVE" if self.flooder_enabled else "INACTIVE"
            self.logger.log(f"Identity Flooder toggled: {state}")

    def _process_event(self, event: Dict[str, Any]):
        if event["type"] == "identity_access":
            self._handle_identity_access(event)

    def _handle_identity_access(self, event: Dict[str, Any]):
        persona = FakePersona(**event["persona"])
        lid = event["effective_lid"]
        shadow_active = event["shadow_active"]
        kill_switch = event["kill_switch"]
        auto_kill = event["auto_kill"]
        stealth_mode = event["stealth_mode"]
        subsystem = event["subsystem"]

        glyph = self._glyph_for_state(shadow_active, kill_switch, stealth_mode)
        mode_tags = []
        if kill_switch:
            mode_tags.append("KillSwitch")
        if shadow_active:
            mode_tags.append("Shadow")
        if auto_kill:
            mode_tags.append("AutoKill")
        if stealth_mode:
            mode_tags.append("Stealth")
        if self.flooder_enabled:
            mode_tags.append("Flooder")
        if self.persona_engine.get_swarm_state():
            mode_tags.append("Swarm")

        tag_str = ",".join(mode_tags) if mode_tags else "Normal"

        msg = (
            f"{glyph} Identity access by [{subsystem}] -> "
            f"LID={lid} modes=[{tag_str}] "
            f"persona={persona.id} fp={persona.device_fingerprint} "
            f"activity={persona.activity_profile} sync={persona.sync_state} "
            f"risk={persona.risk_level}"
        )
        self.logger.log(msg)

        if self.flooder_enabled:
            self._identity_flood(subsystem)

    def _glyph_for_state(self, shadow_active: bool, kill_switch: bool, stealth_mode: bool) -> str:
        if stealth_mode:
            return "□"  # identity-null
        if kill_switch:
            return "■"  # hard block
        if shadow_active:
            return "●"  # shadow active
        return "▲"      # potential leak

    def _identity_flood(self, subsystem: str):
        for i in range(3):
            persona = self.persona_engine.get_persona(f"{subsystem}-Flood-{i}")
            fake_lid = random.getrandbits(64)
            glyph = "◆"
            msg = (
                f"{glyph} Flood event [{i}] for subsystem [{subsystem}] -> "
                f"LID={fake_lid} persona={persona.id} fp={persona.device_fingerprint} "
                f"activity={persona.activity_profile} sync={persona.sync_state} "
                f"risk={persona.risk_level}"
            )
            self.logger.log(msg)


# ============================================================
# Honeypot Sandbox (Telemetry Log)
# ============================================================

class HoneypotSandbox:
    def __init__(self, logger: SafeLogger):
        self.logger = logger
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_event(self, event: Dict[str, Any]):
        with self._lock:
            self._events.append(event)
        self.logger.log(f"Honeypot recorded event: {event.get('type', 'unknown')}")

    def get_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return self._events[-limit:]


# ============================================================
# GUI (Glyph-coded warning system + all toggles)
# ============================================================

class CodexGUI:
    """
    Tkinter-based GUI for controlling Identity Shadow Layer and viewing telemetry.
    Includes:
    - Shadow toggle
    - Kill Switch toggle
    - Auto-Kill toggle
    - Stealth Mode toggle
    - Persona Lock toggle
    - Persona Swarm toggle
    - Identity Flooder toggle
    - Glyph-coded status indicators
    """
    def __init__(
        self,
        root: tk.Tk,
        logger: SafeLogger,
        identity_shadow: IdentityShadowLayer,
        persona_engine: PersonaEngine,
        telemetry_engine: FakeTelemetryEngine,
    ):
        self.root = root
        self.logger = logger
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.telemetry_engine = telemetry_engine

        self.root.title("Codex Purge Shell – Identity Shadow Layer v4")
        self.root.geometry("1100x700")

        self._build_layout()
        self._refresh_ui()
        self._schedule_refresh()

    def _build_layout(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Identity Shadow Panel
        self.shadow_frame = ttk.LabelFrame(self.main_frame, text="Identity Shadow Layer")
        self.shadow_frame.pack(fill=tk.X, padx=5, pady=5)

        self.shadow_status_label = ttk.Label(self.shadow_frame, text="Shadow Status: Unknown")
        self.shadow_status_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.shadow_toggle_btn = ttk.Button(
            self.shadow_frame, text="Toggle Shadow ON/OFF", command=self._toggle_shadow
        )
        self.shadow_toggle_btn.grid(row=0, column=1, sticky="e", padx=5, pady=5)

        self.kill_switch_label = ttk.Label(self.shadow_frame, text="Kill Switch: Unknown")
        self.kill_switch_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self.kill_switch_btn = ttk.Button(
            self.shadow_frame, text="Toggle Kill Switch", command=self._toggle_kill_switch
        )
        self.kill_switch_btn.grid(row=1, column=1, sticky="e", padx=5, pady=5)

        self.auto_kill_label = ttk.Label(self.shadow_frame, text="Auto-Kill: Unknown")
        self.auto_kill_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.auto_kill_btn = ttk.Button(
            self.shadow_frame, text="Toggle Auto-Kill", command=self._toggle_auto_kill
        )
        self.auto_kill_btn.grid(row=2, column=1, sticky="e", padx=5, pady=5)

        self.stealth_label = ttk.Label(self.shadow_frame, text="Stealth Mode: Unknown")
        self.stealth_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)

        self.stealth_btn = ttk.Button(
            self.shadow_frame, text="Toggle Stealth Mode", command=self._toggle_stealth
        )
        self.stealth_btn.grid(row=3, column=1, sticky="e", padx=5, pady=5)

        self.rotate_lid_btn = ttk.Button(
            self.shadow_frame, text="Rotate Fake LID Now", command=self._rotate_fake_lid
        )
        self.rotate_lid_btn.grid(row=0, column=2, sticky="e", padx=5, pady=5)

        self.shadow_info_text = tk.Text(self.shadow_frame, height=7, width=120)
        self.shadow_info_text.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

        # Persona Panel
        self.persona_frame = ttk.LabelFrame(self.main_frame, text="Fake Persona Metadata")
        self.persona_frame.pack(fill=tk.X, padx=5, pady=5)

        self.persona_info_text = tk.Text(self.persona_frame, height=8, width=120)
        self.persona_info_text.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        self.rotate_persona_btn = ttk.Button(
            self.persona_frame, text="Rotate Persona", command=self._rotate_persona
        )
        self.rotate_persona_btn.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self.persona_lock_label = ttk.Label(self.persona_frame, text="Persona Lock: Unknown")
        self.persona_lock_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        self.persona_lock_btn = ttk.Button(
            self.persona_frame, text="Toggle Persona Lock", command=self._toggle_persona_lock
        )
        self.persona_lock_btn.grid(row=1, column=2, sticky="e", padx=5, pady=5)

        self.swarm_label = ttk.Label(self.persona_frame, text="Persona Swarm: Unknown")
        self.swarm_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.swarm_btn = ttk.Button(
            self.persona_frame, text="Toggle Persona Swarm", command=self._toggle_swarm
        )
        self.swarm_btn.grid(row=2, column=1, sticky="e", padx=5, pady=5)

        # Telemetry Panel
        self.telemetry_frame = ttk.LabelFrame(self.main_frame, text="Identity Access Log (Glyph-coded)")
        self.telemetry_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.telemetry_text = tk.Text(self.telemetry_frame, height=15, width=120)
        self.telemetry_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.simulate_access_btn = ttk.Button(
            self.telemetry_frame,
            text="Simulate Identity Access (Edge Sync)",
            command=lambda: self._simulate_identity_access("EdgeSync"),
        )
        self.simulate_access_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.simulate_access2_btn = ttk.Button(
            self.telemetry_frame,
            text="Simulate Identity Access (Store)",
            command=lambda: self._simulate_identity_access("MicrosoftStore"),
        )
        self.simulate_access2_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.simulate_access3_btn = ttk.Button(
            self.telemetry_frame,
            text="Simulate Identity Access (Telemetry)",
            command=lambda: self._simulate_identity_access("Telemetry"),
        )
        self.simulate_access3_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.refresh_log_btn = ttk.Button(
            self.telemetry_frame, text="Refresh Log", command=self._refresh_log
        )
        self.refresh_log_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        self.flooder_label = ttk.Label(self.telemetry_frame, text="Identity Flooder: Unknown")
        self.flooder_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.flooder_btn = ttk.Button(
            self.telemetry_frame, text="Toggle Flooder", command=self._toggle_flooder
        )
        self.flooder_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Glyph Legend
        self.legend_frame = ttk.LabelFrame(self.main_frame, text="Glyph Legend")
        self.legend_frame.pack(fill=tk.X, padx=5, pady=5)

        legend_text = (
            "■ Kill Switch / Lockdown ACTIVE – hard block, real identity never leaves.\n"
            "● Shadow ACTIVE – fake identity used, real identity shadowed.\n"
            "▲ Shadow OFF & Kill Switch OFF – potential leak, Leak Detector watching.\n"
            "□ Stealth Mode ACTIVE – identity-null, machine appears anonymous.\n"
            "◆ Flood event – Identity Flooder generating fake identity noise."
        )
        self.legend_label = ttk.Label(self.legend_frame, text=legend_text, justify="left")
        self.legend_label.pack(fill=tk.X, padx=5, pady=5)

    def _toggle_shadow(self):
        snapshot = self.identity_shadow.get_state_snapshot()
        if snapshot["active"]:
            self.identity_shadow.deactivate()
        else:
            self.identity_shadow.activate()
        self._refresh_ui()

    def _toggle_kill_switch(self):
        self.identity_shadow.toggle_kill_switch()
        self._refresh_ui()

    def _toggle_auto_kill(self):
        self.identity_shadow.toggle_auto_kill()
        self._refresh_ui()

    def _toggle_stealth(self):
        self.identity_shadow.toggle_stealth_mode()
        self._refresh_ui()

    def _rotate_fake_lid(self):
        self.identity_shadow.rotate_fake_lid()
        self._refresh_ui()

    def _rotate_persona(self):
        self.persona_engine.rotate_persona()
        self._refresh_ui()

    def _toggle_persona_lock(self):
        self.persona_engine.toggle_lock()
        self._refresh_ui()

    def _toggle_swarm(self):
        self.persona_engine.toggle_swarm()
        self._refresh_ui()

    def _toggle_flooder(self):
        self.telemetry_engine.toggle_flooder()
        self._refresh_ui()

    def _simulate_identity_access(self, subsystem: str):
        self.telemetry_engine.submit_identity_access(subsystem)

    def _refresh_ui(self):
        snapshot = self.identity_shadow.get_state_snapshot()
        status = "ACTIVE" if snapshot["active"] else "INACTIVE"
        kill_state = "ACTIVE" if snapshot["kill_switch"] else "INACTIVE"
        auto_kill_state = "ACTIVE" if snapshot["auto_kill"] else "INACTIVE"
        stealth_state = "ACTIVE" if snapshot["stealth_mode"] else "INACTIVE"

        glyph = "●" if snapshot["active"] else "▲"
        if snapshot["kill_switch"] or time.time() < snapshot["reboot_lockdown_until"]:
            glyph = "■"
        if snapshot["stealth_mode"]:
            glyph = "□"

        self.shadow_status_label.config(text=f"Shadow Status: {status} {glyph}")
        try:
            color = "green" if snapshot["active"] else "red"
            if snapshot["kill_switch"] or time.time() < snapshot["reboot_lockdown_until"]:
                color = "purple"
            if snapshot["stealth_mode"]:
                color = "blue"
            self.shadow_status_label.config(foreground=color)
        except Exception:
            pass

        self.kill_switch_label.config(text=f"Kill Switch: {kill_state} ■")
        self.auto_kill_label.config(text=f"Auto-Kill: {auto_kill_state}")
        self.stealth_label.config(text=f"Stealth Mode: {stealth_state} □")

        self.shadow_info_text.delete("1.0", tk.END)
        self.shadow_info_text.insert(
            tk.END,
            json.dumps(snapshot, indent=2),
        )

        persona = self.persona_engine.get_persona("GUI")
        self.persona_info_text.delete("1.0", tk.END)
        self.persona_info_text.insert(
            tk.END,
            json.dumps(persona.__dict__, indent=2),
        )

        lock_state = "ACTIVE" if self.persona_engine.get_lock_state() else "INACTIVE"
        self.persona_lock_label.config(text=f"Persona Lock: {lock_state}")

        swarm_state = "ACTIVE" if self.persona_engine.get_swarm_state() else "INACTIVE"
        self.swarm_label.config(text=f"Persona Swarm: {swarm_state}")

        flood_state = "ACTIVE" if self.telemetry_engine.flooder_enabled else "INACTIVE"
        self.flooder_label.config(text=f"Identity Flooder: {flood_state}")

        self._refresh_log()

    def _refresh_log(self):
        recent = logger.get_recent(limit=100)
        self.telemetry_text.delete("1.0", tk.END)
        for line in recent:
            self.telemetry_text.insert(tk.END, line + "\n")

    def _schedule_refresh(self):
        self.root.after(1000, self._periodic_refresh)

    def _periodic_refresh(self):
        self._refresh_ui()
        self._schedule_refresh()


# ============================================================
# Main
# ============================================================

logger = SafeLogger()


def main():
    state_store = JsonStateStore("codex_state.json", logger)
    boot_info = compute_boot_info(state_store, logger)

    persona_engine = PersonaEngine(state_store, logger)
    identity_shadow = IdentityShadowLayer(state_store, logger)

    # Apply boot policies
    persona_engine.apply_boot_policies(boot_info)
    identity_shadow.apply_boot_policies(boot_info)

    telemetry_engine = FakeTelemetryEngine(persona_engine, identity_shadow, logger)
    telemetry_engine.start()

    if tk is None or ttk is None:
        logger.log("Tkinter not available; running headless.")
        for name in ["EdgeSync", "MicrosoftStore", "Telemetry"]:
            telemetry_engine.submit_identity_access(name)
            time.sleep(1.0)
        telemetry_engine.stop()
        return

    root = tk.Tk()
    gui = CodexGUI(root, logger, identity_shadow, persona_engine, telemetry_engine)
    root.protocol("WM_DELETE_WINDOW", lambda: (telemetry_engine.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
