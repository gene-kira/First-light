#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Purge Shell – Unified Python File
Fake Telemetry + Persona Engine + IdentityCRL Shadow Layer
GUI-controlled ON/OFF toggle for Identity Shadow Layer

NOTE:
- This is a safe, non-destructive architecture.
- Registry access, firewall control, and OS hooks are simulated/stubbed.
- You can wire real integrations where marked with TODOs.
"""

import sys
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
    Simple JSON persistence for persona + identity shadow state.
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
# Persona Engine
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
    """
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self.current_persona: Optional[FakePersona] = None
        self._lock = threading.Lock()
        self._load_or_create_persona()

    def _load_or_create_persona(self):
        data = self.state_store.get("persona", None)
        if data:
            self.current_persona = FakePersona(**data)
            self.logger.log("Loaded existing fake persona from state.")
        else:
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.logger.log("Generated new fake persona.")

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

    def _persist_persona(self):
        if self.current_persona:
            self.state_store.set("persona", self.current_persona.__dict__)

    def rotate_persona(self):
        with self._lock:
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.logger.log("Persona rotated.")

    def get_persona(self) -> FakePersona:
        with self._lock:
            return self.current_persona


# ============================================================
# IdentityCRL Shadow Layer
# ============================================================

@dataclass
class IdentityShadowState:
    real_lid_hex: Optional[str] = None
    real_lid_numeric: Optional[int] = None
    fake_lid_numeric: Optional[int] = None
    active: bool = False
    last_rotation_ts: float = 0.0


class IdentityShadowLayer:
    """
    Safe, non-destructive IdentityCRL shadow layer.
    - Reads real LID (stubbed).
    - Generates fake LID.
    - Provides fake identity when active.
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
        # Stub: simulate reading real LID from registry safely
        # In real implementation, you would use winreg and read:
        # HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties\LID
        self.state.real_lid_hex = f"{random.getrandbits(64):016x}"
        self.state.real_lid_numeric = int(self.state.real_lid_hex, 16)
        self.state.fake_lid_numeric = self._generate_fake_lid()
        self.state.active = False
        self.state.last_rotation_ts = time.time()
        self.logger.log(
            f"Initialized Identity Shadow: real_hex={self.state.real_lid_hex}, "
            f"real_numeric={self.state.real_lid_numeric}, fake={self.state.fake_lid_numeric}"
        )

    def _persist_state(self):
        self.state_store.set("identity_shadow", self.state.__dict__)

    def _generate_fake_lid(self) -> int:
        # Generate a plausible 64-bit integer for fake LID
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

    def rotate_fake_lid(self):
        with self._lock:
            self.state.fake_lid_numeric = self._generate_fake_lid()
            self.state.last_rotation_ts = time.time()
            self.logger.log("Fake LID rotated.")
            self._persist_state()

    def get_effective_lid(self) -> int:
        """
        Returns the LID that should be used by higher layers.
        If active, returns fake LID; otherwise returns real LID.
        """
        with self._lock:
            if self.state.active and self.state.fake_lid_numeric is not None:
                return self.state.fake_lid_numeric
            return self.state.real_lid_numeric or 0

    def get_state_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "real_lid_hex": self.state.real_lid_hex,
                "real_lid_numeric": self.state.real_lid_numeric,
                "fake_lid_numeric": self.state.fake_lid_numeric,
                "active": self.state.active,
                "last_rotation_ts": self.state.last_rotation_ts,
            }


# ============================================================
# Fake Telemetry Engine
# ============================================================

class FakeTelemetryEngine:
    """
    Uses PersonaEngine + IdentityShadowLayer to generate fake telemetry.
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
        """
        Called when some subsystem 'requests' identity.
        This is a simulation hook.
        """
        persona = self.persona_engine.get_persona()
        effective_lid = self.identity_shadow.get_effective_lid()
        event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona_id": persona.id,
            "effective_lid": effective_lid,
            "shadow_active": self.identity_shadow.get_state_snapshot()["active"],
            "ts": time.time(),
        }
        self._event_queue.put(event)

    def _process_event(self, event: Dict[str, Any]):
        if event["type"] == "identity_access":
            self._handle_identity_access(event)

    def _handle_identity_access(self, event: Dict[str, Any]):
        persona = self.persona_engine.get_persona()
        lid = event["effective_lid"]
        shadow_active = event["shadow_active"]
        subsystem = event["subsystem"]
        msg = (
            f"Identity access by [{subsystem}] -> "
            f"LID={lid} (shadow_active={shadow_active}) "
            f"persona={persona.id} fp={persona.device_fingerprint} "
            f"activity={persona.activity_profile} sync={persona.sync_state} "
            f"risk={persona.risk_level}"
        )
        self.logger.log(msg)


# ============================================================
# Honeypot Sandbox (Telemetry Log)
# ============================================================

class HoneypotSandbox:
    """
    Simple honeypot-like logger for identity and telemetry events.
    """
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
# GUI
# ============================================================

class CodexGUI:
    """
    Tkinter-based GUI for controlling Identity Shadow Layer and viewing telemetry.
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

        self.root.title("Codex Purge Shell – Identity Shadow Layer")
        self.root.geometry("900x600")

        self._build_layout()
        self._refresh_ui()
        self._schedule_refresh()

    def _build_layout(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Identity Shadow Panel
        self.shadow_frame = ttk.LabelFrame(self.main_frame, text="Identity Shadow Layer")
        self.shadow_frame.pack(fill=tk.X, padx=5, pady=5)

        self.shadow_status_label = ttk.Label(self.shadow_frame, text="Status: Unknown")
        self.shadow_status_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.shadow_toggle_btn = ttk.Button(
            self.shadow_frame, text="Toggle ON/OFF", command=self._toggle_shadow
        )
        self.shadow_toggle_btn.grid(row=0, column=1, sticky="e", padx=5, pady=5)

        self.rotate_lid_btn = ttk.Button(
            self.shadow_frame, text="Rotate Fake LID Now", command=self._rotate_fake_lid
        )
        self.rotate_lid_btn.grid(row=0, column=2, sticky="e", padx=5, pady=5)

        self.shadow_info_text = tk.Text(self.shadow_frame, height=5, width=80)
        self.shadow_info_text.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        # Persona Panel
        self.persona_frame = ttk.LabelFrame(self.main_frame, text="Fake Persona Metadata")
        self.persona_frame.pack(fill=tk.X, padx=5, pady=5)

        self.persona_info_text = tk.Text(self.persona_frame, height=6, width=80)
        self.persona_info_text.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

        self.rotate_persona_btn = ttk.Button(
            self.persona_frame, text="Rotate Persona", command=self._rotate_persona
        )
        self.rotate_persona_btn.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        # Telemetry Panel
        self.telemetry_frame = ttk.LabelFrame(self.main_frame, text="Identity Access Log")
        self.telemetry_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.telemetry_text = tk.Text(self.telemetry_frame, height=15, width=80)
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

        self.refresh_log_btn = ttk.Button(
            self.telemetry_frame, text="Refresh Log", command=self._refresh_log
        )
        self.refresh_log_btn.pack(side=tk.RIGHT, padx=5, pady=5)

    def _toggle_shadow(self):
        snapshot = self.identity_shadow.get_state_snapshot()
        if snapshot["active"]:
            self.identity_shadow.deactivate()
        else:
            self.identity_shadow.activate()
        self._refresh_ui()

    def _rotate_fake_lid(self):
        self.identity_shadow.rotate_fake_lid()
        self._refresh_ui()

    def _rotate_persona(self):
        self.persona_engine.rotate_persona()
        self._refresh_ui()

    def _simulate_identity_access(self, subsystem: str):
        self.telemetry_engine.submit_identity_access(subsystem)

    def _refresh_ui(self):
        # Shadow status
        snapshot = self.identity_shadow.get_state_snapshot()
        status = "ACTIVE" if snapshot["active"] else "INACTIVE"
        color = "green" if snapshot["active"] else "red"
        self.shadow_status_label.config(text=f"Status: {status}")
        try:
            self.shadow_status_label.config(foreground=color)
        except Exception:
            pass

        self.shadow_info_text.delete("1.0", tk.END)
        self.shadow_info_text.insert(
            tk.END,
            json.dumps(snapshot, indent=2),
        )

        # Persona info
        persona = self.persona_engine.get_persona()
        self.persona_info_text.delete("1.0", tk.END)
        self.persona_info_text.insert(
            tk.END,
            json.dumps(persona.__dict__, indent=2),
        )

        # Telemetry log
        self._refresh_log()

    def _refresh_log(self):
        # For now, we just read from stdout logger buffer
        recent = logger.get_recent(limit=50)
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
    persona_engine = PersonaEngine(state_store, logger)
    identity_shadow = IdentityShadowLayer(state_store, logger)
    telemetry_engine = FakeTelemetryEngine(persona_engine, identity_shadow, logger)
    telemetry_engine.start()

    if tk is None or ttk is None:
        logger.log("Tkinter not available; running headless.")
        # Headless simulation loop
        for i in range(5):
            telemetry_engine.submit_identity_access("HeadlessSubsystem")
            time.sleep(1.0)
        telemetry_engine.stop()
        return

    root = tk.Tk()
    gui = CodexGUI(root, logger, identity_shadow, persona_engine, telemetry_engine)
    root.protocol("WM_DELETE_WINDOW", lambda: (telemetry_engine.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
