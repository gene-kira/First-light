#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Purge Shell – v11 (Full Rewrite, Monolithic, Optional Qt GUI)
Unified Event Bus + Agentic Core + Identity Shadow v4 + Persona v4 + Suricata v7 (simulated)
GPU Inference v2 + Raft/Paxos Mesh v2 + Telemetry Mirage v4 + Self-Healing v2

All behavior is simulated and safe (no destructive OS changes).
"""

import json
import time
import threading
import random
import queue
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable

# ============================================================
# Qt Imports (Optional GUI)
# ============================================================

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except ImportError:
    QtWidgets = None
    QtCore = None
    QtGui = None


# ============================================================
# Core Utilities
# ============================================================

class SafeLogger:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries: List[str] = []
        self.low_noise_mode: bool = False
        self.max_entries: int = 600

    def log(self, msg: str, force: bool = False):
        if self.low_noise_mode and not force:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{ts}] {msg}"
        with self._lock:
            self._entries.append(line)
            if len(self._entries) > self.max_entries:
                self._entries = self._entries[-self.max_entries:]
        print(line)

    def get_recent(self, limit: int = 80) -> List[str]:
        with self._lock:
            return self._entries[-limit:]

    def set_low_noise(self, enabled: bool):
        self.low_noise_mode = enabled
        self.log(f"[Logger] Low-noise mode set to {enabled}", force=True)


class JsonStateStoreV3:
    """
    Unified JSON state store v3:
    - atomic writes
    - versioning
    - schema hints
    - auto-repair (best-effort)
    """
    def __init__(self, path: str, logger: SafeLogger):
        self.path = path
        self.logger = logger
        self.state: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self.version_key = "_state_version"
        self.version = 3
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.state = json.load(f)
            self.logger.log(f"[StateStore] Loaded state from {self.path}")
        except FileNotFoundError:
            self.logger.log(f"[StateStore] No existing state file at {self.path}, starting fresh.")
            self.state = {}
        except Exception as e:
            self.logger.log(f"[StateStore] Error loading state: {e}")
            self.state = {}
        with self._lock:
            if self.version_key not in self.state:
                self.state[self.version_key] = self.version

    def save(self):
        with self._lock:
            self.state[self.version_key] = self.version
            tmp_path = self.path + ".tmp"
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(self.state, f, indent=2)
                # atomic replace
                import os
                os.replace(tmp_path, self.path)
                self.logger.log(f"[StateStore] State saved atomically to {self.path}")
            except Exception as e:
                self.logger.log(f"[StateStore] Error saving state: {e}")

    def get(self, key: str, default=None):
        with self._lock:
            return self.state.get(key, default)

    def set(self, key: str, value: Any):
        with self._lock:
            self.state[key] = value
        self.save()

    def ensure_key(self, key: str, default: Any):
        with self._lock:
            if key not in self.state:
                self.state[key] = default
        self.save()


# ============================================================
# Unified Event Bus
# ============================================================

@dataclass
class Event:
    type: str
    payload: Dict[str, Any]
    ts: float = field(default_factory=lambda: time.time())


class EventBus:
    def __init__(self, logger: SafeLogger):
        self.logger = logger
        self._subscribers: Dict[str, List[Callable[[Event], None]]] = {}
        self._queue: "queue.Queue[Event]" = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def subscribe(self, event_type: str, handler: Callable[[Event], None]):
        handlers = self._subscribers.setdefault(event_type, [])
        handlers.append(handler)
        self.logger.log(f"[EventBus] Handler subscribed to {event_type}", force=True)

    def publish(self, event: Event):
        self._queue.put(event)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.log("[EventBus] Started.")

    def stop(self):
        self._running = False
        self.logger.log("[EventBus] Stopped.")

    def _loop(self):
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            handlers = self._subscribers.get(event.type, [])
            for h in handlers:
                try:
                    h(event)
                except Exception as e:
                    self.logger.log(f"[EventBus] Handler error for {event.type}: {e}")


# ============================================================
# Boot Metadata / Integrity Check
# ============================================================

@dataclass
class BootInfo:
    first_boot: bool
    last_boot_ts: float
    current_boot_ts: float
    reboot_interval_sec: float


def compute_boot_info(state_store: JsonStateStoreV3, logger: SafeLogger) -> BootInfo:
    current_ts = time.time()
    last_boot_ts = state_store.get("last_boot_ts", 0.0)
    first_boot_done = bool(state_store.get("first_boot_done", False))

    first_boot = not first_boot_done
    reboot_interval = current_ts - last_boot_ts if last_boot_ts > 0 else 0.0

    if first_boot:
        logger.log("[IntegrityCheck] First boot detected. Validating state structure.")
        for key in [
            "persona",
            "identity_shadow",
            "ml_patterns",
            "quarantine",
            "threat_scores",
            "persona_memory",
            "reputation",
            "suricata_rules",
            "mesh_state",
            "threat_matrix",
        ]:
            if key not in state_store.state:
                logger.log(f"[IntegrityCheck] Missing key '{key}' in state (expected on first boot).")
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
# Persona Engine v4
# ============================================================

@dataclass
class PersonaMemoryEntry:
    ts: float
    event_type: str
    details: Dict[str, Any]


@dataclass
class FakePersona:
    id: str
    device_fingerprint: str
    activity_profile: str
    sync_state: str
    risk_level: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    memory: List[PersonaMemoryEntry] = field(default_factory=list)


class PersonaForgeV4:
    def __init__(self):
        self.regions = ["US", "EU", "APAC", "LATAM", "MEA"]
        self.roles = ["workstation", "lab-node", "honeypot", "gaming-rig", "dev-box", "test-bench"]
        self.activity_profiles = ["idle", "light", "moderate", "heavy", "burst"]
        self.sync_states = ["in-sync", "lagging", "desynced", "partial-sync"]
        self.risk_levels = ["low", "medium", "high"]
        self.app_stacks = [
            ["Edge", "Office", "Teams"],
            ["Chrome", "VSCode", "Git"],
            ["Steam", "Discord", "Browser"],
            ["SecuritySuite", "AdminTools", "PowerShell"],
        ]
        self.network_styles = ["home", "lab", "corp", "vpn", "mixed"]

    def forge_persona(self) -> FakePersona:
        pid = f"persona-{random.randint(10**8, 10**9-1)}"
        fingerprint = f"FP-{random.randint(10**12, 10**13-1)}"
        activity = random.choice(self.activity_profiles)
        sync_state = random.choice(self.sync_states)
        risk = random.choice(self.risk_levels)
        region = random.choice(self.regions)
        role = random.choice(self.roles)
        apps = random.choice(self.app_stacks)
        net_style = random.choice(self.network_styles)
        metadata = {
            "os_profile": random.choice(["Windows-Shadow", "Windows-Edge", "Windows-Null"]),
            "region": region,
            "role": role,
            "timezone": random.choice(["UTC-5", "UTC+1", "UTC+8"]),
            "usage_pattern": random.choice(["office-hours", "night-owl", "mixed"]),
            "apps": apps,
            "network_style": net_style,
            "lineage_tag": f"lineage-{random.randint(1000,9999)}",
            "evolution_stage": 0,
        }
        return FakePersona(
            id=pid,
            device_fingerprint=fingerprint,
            activity_profile=activity,
            sync_state=sync_state,
            risk_level=risk,
            metadata=metadata,
            memory=[],
        )

    def evolve_persona(self, persona: FakePersona, threat_level: float, cluster_threat: float) -> FakePersona:
        stage = persona.metadata.get("evolution_stage", 0) + 1
        persona.metadata["evolution_stage"] = stage

        # Behavior-driven evolution
        if threat_level > 50 or cluster_threat > 50:
            persona.activity_profile = random.choice(["heavy", "burst"])
            persona.sync_state = random.choice(["lagging", "desynced"])
            persona.risk_level = random.choice(["medium", "high"])
        else:
            persona.activity_profile = random.choice(["idle", "light", "moderate"])

        if stage % 2 == 0:
            persona.metadata["region"] = random.choice(self.regions)
        if stage % 3 == 0:
            persona.metadata["apps"] = random.choice(self.app_stacks)
        if stage % 4 == 0:
            persona.sync_state = random.choice(self.sync_states)
        if stage % 5 == 0:
            persona.device_fingerprint = f"FP-{random.randint(10**12, 10**13-1)}"

        return persona


class PersonaEngineV4:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger, forge: PersonaForgeV4):
        self.state_store = state_store
        self.logger = logger
        self.forge = forge
        self._lock = threading.Lock()

        self.current_persona: Optional[FakePersona] = None
        self.persona_locked: bool = False

        self.swarm_enabled: bool = False
        self.swarm_personas: List[FakePersona] = []
        self.swarm_target_size: int = 6

        self.last_rotation_ts: float = time.time()
        self.rotation_interval_sec: float = 900

        self._load_or_create_persona()
        self._load_lock_state()
        self._load_swarm_state()
        self._load_persona_memory()

        self._rotation_thread = threading.Thread(target=self._rotation_loop, daemon=True)
        self._rotation_thread.start()

    def _load_or_create_persona(self):
        data = self.state_store.get("persona", None)
        if data:
            try:
                mem_data = self.state_store.get("persona_memory", [])
                memory = [
                    PersonaMemoryEntry(
                        ts=entry.get("ts", 0.0),
                        event_type=entry.get("event_type", ""),
                        details=entry.get("details", {}),
                    )
                    for entry in mem_data
                ]
                data["memory"] = memory
                self.current_persona = FakePersona(**data)
                self.logger.log("[PersonaEngine] Loaded existing persona with memory.")
            except Exception as e:
                self.logger.log(f"[PersonaEngine] Error loading persona: {e}")
                self.current_persona = self.forge.forge_persona()
                self._persist_persona()
        else:
            self.current_persona = self.forge.forge_persona()
            self._persist_persona()
            self.logger.log("[PersonaEngine] Generated new persona via Forge v4.")

    def _load_lock_state(self):
        locked = self.state_store.get("persona_locked", False)
        self.persona_locked = bool(locked)
        self.logger.log(f"[PersonaEngine] Persona lock state loaded: locked={self.persona_locked}")

    def _load_swarm_state(self):
        swarm_data = self.state_store.get("persona_swarm", None)
        self.swarm_enabled = bool(self.state_store.get("swarm_enabled", False))
        if swarm_data:
            try:
                self.swarm_personas = []
                for p in swarm_data:
                    mem_data = p.get("memory", [])
                    memory = [
                        PersonaMemoryEntry(
                            ts=entry.get("ts", 0.0),
                            event_type=entry.get("event_type", ""),
                            details=entry.get("details", {}),
                        )
                        for entry in mem_data
                    ]
                    p["memory"] = memory
                    self.swarm_personas.append(FakePersona(**p))
                self.logger.log(f"[PersonaEngine] Loaded swarm with {len(self.swarm_personas)} personas.")
            except Exception as e:
                self.logger.log(f"[PersonaEngine] Error loading swarm: {e}")
                self.swarm_personas = []
        else:
            self.swarm_personas = []

    def _load_persona_memory(self):
        mem_data = self.state_store.get("persona_memory", [])
        if self.current_persona:
            try:
                memory = [
                    PersonaMemoryEntry(
                        ts=entry.get("ts", 0.0),
                        event_type=entry.get("event_type", ""),
                        details=entry.get("details", {}),
                    )
                    for entry in mem_data
                ]
                self.current_persona.memory = memory
                self.logger.log(f"[PersonaEngine] Loaded persona memory with {len(memory)} entries.")
            except Exception as e:
                self.logger.log(f"[PersonaEngine] Error loading persona memory: {e}")

    def _persist_persona(self):
        if self.current_persona:
            data = self.current_persona.__dict__.copy()
            mem_data = [
                {"ts": m.ts, "event_type": m.event_type, "details": m.details}
                for m in self.current_persona.memory
            ]
            data["memory"] = mem_data
            self.state_store.set("persona", data)
            self.state_store.set("persona_memory", mem_data)

    def _persist_lock_state(self):
        self.state_store.set("persona_locked", self.persona_locked)

    def _persist_swarm_state(self):
        swarm_data = []
        for p in self.swarm_personas:
            d = p.__dict__.copy()
            d["memory"] = [
                {"ts": m.ts, "event_type": m.event_type, "details": m.details}
                for m in p.memory
            ]
            swarm_data.append(d)
        self.state_store.set("persona_swarm", swarm_data)
        self.state_store.set("swarm_enabled", self.swarm_enabled)

    def rotate_persona(self, reason: str = "manual"):
        with self._lock:
            if self.persona_locked:
                self.logger.log(f"[PersonaEngine] Rotation requested ({reason}) but lock ACTIVE.")
                return
            self.current_persona = self.forge.forge_persona()
            self._persist_persona()
            self.last_rotation_ts = time.time()
            self.logger.log(f"[PersonaEngine] Persona rotated via Forge v4 (reason={reason}).")

    def evolve_current_persona(self, threat_level: float, cluster_threat: float, reason: str = "adaptive"):
        with self._lock:
            if not self.current_persona:
                return
            self.current_persona = self.forge.evolve_persona(self.current_persona, threat_level, cluster_threat)
            self._persist_persona()
            self.logger.log(
                f"[PersonaEngine] Persona evolved (reason={reason}) stage={self.current_persona.metadata.get('evolution_stage')}."
            )

    def _rotation_loop(self):
        while True:
            time.sleep(5)
            with self._lock:
                if self.persona_locked:
                    continue
                now = time.time()
                if now - self.last_rotation_ts >= self.rotation_interval_sec:
                    self.rotate_persona(reason="scheduled")
                else:
                    if random.random() < 0.03:
                        self.evolve_current_persona(threat_level=0.0, cluster_threat=0.0, reason="background")

    def get_persona(self, subsystem: str = "") -> FakePersona:
        with self._lock:
            if self.swarm_enabled and self.swarm_personas:
                idx = random.randint(0, len(self.swarm_personas) - 1)
                persona = self.swarm_personas[idx]
                self.logger.log(
                    f"[PersonaEngine] Swarm selected persona [{persona.id}] for subsystem [{subsystem}]."
                )
                return persona
            return self.current_persona

    def add_memory_event(self, persona: FakePersona, event_type: str, details: Dict[str, Any]):
        entry = PersonaMemoryEntry(ts=time.time(), event_type=event_type, details=details)
        persona.memory.append(entry)
        if len(persona.memory) > 80:
            persona.memory = persona.memory[-80:]
        if persona is self.current_persona:
            self._persist_persona()

    def toggle_lock(self):
        with self._lock:
            self.persona_locked = not self.persona_locked
            self._persist_lock_state()
            state = "ACTIVE" if self.persona_locked else "INACTIVE"
            self.logger.log(f"[PersonaEngine] Persona Lock toggled: {state}")

    def get_lock_state(self) -> bool:
        with self._lock:
            return self.persona_locked

    def toggle_swarm(self):
        with self._lock:
            self.swarm_enabled = not self.swarm_enabled
            if self.swarm_enabled and len(self.swarm_personas) < self.swarm_target_size:
                needed = self.swarm_target_size - len(self.swarm_personas)
                for _ in range(needed):
                    self.swarm_personas.append(self.forge.forge_persona())
                self.logger.log(
                    f"[PersonaEngine] Swarm initialized/expanded to {len(self.swarm_personas)} personas."
                )
            self._persist_swarm_state()
            state = "ACTIVE" if self.swarm_enabled else "INACTIVE"
            self.logger.log(f"[PersonaEngine] Swarm toggled: {state}")

    def get_swarm_state(self) -> bool:
        with self._lock:
            return self.swarm_enabled

    def get_swarm_summary(self) -> List[Dict[str, Any]]:
        with self._lock:
            data = []
            for p in self.swarm_personas[:4]:
                d = {
                    "id": p.id,
                    "region": p.metadata.get("region"),
                    "role": p.metadata.get("role"),
                    "risk": p.risk_level,
                    "stage": p.metadata.get("evolution_stage"),
                }
                data.append(d)
            return data

    def apply_boot_policies(self, boot_info: BootInfo):
        with self._lock:
            if boot_info.first_boot:
                self.logger.log("[PersonaEngine] BootPolicy: First boot, persona lineage established.")
            else:
                if self.swarm_enabled and self.swarm_personas:
                    resurrect_index = random.randint(0, len(self.swarm_personas) - 1)
                    resurrected = self.swarm_personas[resurrect_index]
                    self.logger.log(
                        f"[PersonaEngine] BootPolicy: Resurrection of [{resurrected.id}] "
                        f"lineage [{resurrected.metadata.get('lineage_tag','?')}]."
                    )
                    self.current_persona = resurrected
                    self._persist_persona()
                else:
                    if not self.persona_locked:
                        self.logger.log("[PersonaEngine] BootPolicy: Reboot -> safe rotation via Forge v4.")
                        self.current_persona = self.forge.forge_persona()
                        self._persist_persona()
                    else:
                        self.logger.log("[PersonaEngine] BootPolicy: Reboot but lock ACTIVE; rotation skipped.")


# ============================================================
# Identity Shadow Layer v4
# ============================================================

@dataclass
class IdentityShadowStateV4:
    real_lid_hex: Optional[str] = None
    real_lid_numeric: Optional[int] = None
    fake_lid_numeric: Optional[int] = None
    active: bool = False
    last_rotation_ts: float = 0.0
    kill_switch: bool = False
    auto_kill: bool = True
    stealth_mode: bool = False
    stealth_tier: int = 0
    reboot_lockdown_until: float = 0.0
    identity_null_decay_ts: float = 0.0
    leak_prediction_score: float = 0.0
    kill_switch_cooldown_until: float = 0.0


class IdentityShadowLayerV4:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self.state = IdentityShadowStateV4()
        self._lock = threading.Lock()
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("identity_shadow", None)
        if data:
            self.state = IdentityShadowStateV4(**data)
            self.logger.log("[IdentityShadow] Loaded state from JSON.")
        else:
            self.logger.log("[IdentityShadow] No state found; initializing fresh.")
            self._init_state()
            self._persist_state()

    def _init_state(self):
        self.state.real_lid_hex = f"{random.getrandbits(64):016x}"
        self.state.real_lid_numeric = int(self.state.real_lid_hex, 16)
        self.state.fake_lid_numeric = self._generate_fake_lid()
        self.state.active = False
        self.state.kill_switch = False
        self.state.auto_kill = True
        self.state.stealth_mode = False
        self.state.stealth_tier = 0
        self.state.reboot_lockdown_until = 0.0
        self.state.last_rotation_ts = time.time()
        self.state.identity_null_decay_ts = 0.0
        self.state.leak_prediction_score = 0.0
        self.state.kill_switch_cooldown_until = 0.0
        self.logger.log(
            f"[IdentityShadow] Initialized v4: real_hex={self.state.real_lid_hex}, "
            f"real_numeric={self.state.real_lid_numeric}, fake={self.state.fake_lid_numeric}"
        )

    def _persist_state(self):
        self.state_store.set("identity_shadow", self.state.__dict__)

    def _generate_fake_lid(self) -> int:
        fake = random.getrandbits(64)
        self.logger.log(f"[IdentityShadow] Generated fake LID: {fake}")
        return fake

    def activate(self):
        with self._lock:
            if not self.state.active:
                self.state.active = True
                self.logger.log("[IdentityShadow] Layer ACTIVATED.")
                self._persist_state()

    def deactivate(self):
        with self._lock:
            if self.state.active:
                self.state.active = False
                self.logger.log("[IdentityShadow] Layer DEACTIVATED.")
                self._persist_state()

    def toggle_kill_switch(self):
        with self._lock:
            now = time.time()
            if self.state.kill_switch and now < self.state.kill_switch_cooldown_until:
                self.logger.log("[IdentityShadow] Kill Switch cooldown active; toggle blocked.")
                return
            self.state.kill_switch = not self.state.kill_switch
            state = "ACTIVE" if self.state.kill_switch else "INACTIVE"
            self.logger.log(f"[IdentityShadow] Kill Switch toggled: {state}")
            if self.state.kill_switch:
                self.state.kill_switch_cooldown_until = now + 120
            self._persist_state()

    def toggle_auto_kill(self):
        with self._lock:
            self.state.auto_kill = not self.state.auto_kill
            state = "ACTIVE" if self.state.auto_kill else "INACTIVE"
            self.logger.log(f"[IdentityShadow] Auto-Kill toggled: {state}")
            self._persist_state()

    def toggle_stealth_mode(self):
        with self._lock:
            self.state.stealth_mode = not self.state.stealth_mode
            if self.state.stealth_mode and self.state.stealth_tier == 0:
                self.state.stealth_tier = 1
            if not self.state.stealth_mode:
                self.state.stealth_tier = 0
            state = "ACTIVE" if self.state.stealth_mode else "INACTIVE"
            self.logger.log(f"[IdentityShadow] Stealth Mode toggled: {state} (tier={self.state.stealth_tier})")
            self._persist_state()

    def set_stealth_tier(self, tier: int):
        with self._lock:
            tier = max(0, min(6, tier))
            self.state.stealth_tier = tier
            self.state.stealth_mode = tier > 0
            self.logger.log(f"[IdentityShadow] Stealth tier set to {tier} (mode={self.state.stealth_mode})")
            self._persist_state()

    def rotate_fake_lid(self):
        with self._lock:
            self.state.fake_lid_numeric = self._generate_fake_lid()
            self.state.last_rotation_ts = time.time()
            self.logger.log("[IdentityShadow] Fake LID rotated.")
            self._persist_state()

    def apply_boot_policies(self, boot_info: BootInfo):
        with self._lock:
            if boot_info.first_boot:
                self.state.stealth_mode = True
                self.state.stealth_tier = 1
                self.logger.log("[IdentityShadow] BootPolicy: First boot -> Stealth tier 1.")
            else:
                lockdown_duration = 300
                self.state.reboot_lockdown_until = boot_info.current_boot_ts + lockdown_duration
                self.logger.log(
                    f"[IdentityShadow] BootPolicy: Reboot -> Lockdown {lockdown_duration}s."
                )
            self._persist_state()

    def _lockdown_active(self) -> bool:
        return time.time() < self.state.reboot_lockdown_until

    def _identity_null_active(self) -> bool:
        return self.state.stealth_mode and self.state.stealth_tier >= 2

    def _identity_cloak_active(self) -> bool:
        return self.state.stealth_mode and self.state.stealth_tier >= 4

    def _temporal_cloak_active(self) -> bool:
        return self.state.stealth_mode and self.state.stealth_tier == 5

    def _quantum_null_active(self) -> bool:
        return self.state.stealth_mode and self.state.stealth_tier == 6

    def update_leak_prediction(self, leak_count: int, burst_count: int):
        with self._lock:
            score = min(100.0, leak_count * 3.0 + burst_count * 2.0)
            self.state.leak_prediction_score = score
            self.logger.log(f"[IdentityShadow] Leak prediction score updated: {score}")
            if score > 60.0 and not self.state.kill_switch:
                self.logger.log("[IdentityShadow] High leak prediction -> Auto Kill Switch.")
                self.state.kill_switch = True
                self._persist_state()

    def get_effective_lid(self, subsystem: str) -> int:
        with self._lock:
            if self._quantum_null_active():
                self.logger.log(
                    f"[IdentityShadow] Stealth-L6 Quantum Null: subsystem {subsystem} gets undefined identity."
                )
                return 0

            if self._identity_cloak_active():
                self.logger.log(
                    f"[IdentityShadow] Stealth-L4+ cloak: subsystem {subsystem} gets identity-void."
                )
                return 0

            if self._identity_null_active():
                self.logger.log(
                    f"[IdentityShadow] Stealth-L{self.state.stealth_tier} null: subsystem {subsystem} gets null identity."
                )
                return 0

            if self.state.kill_switch or self._lockdown_active():
                if self.state.fake_lid_numeric is None:
                    self.state.fake_lid_numeric = self._generate_fake_lid()
                    self._persist_state()
                if self._lockdown_active():
                    self.logger.log(
                        f"[IdentityShadow] Lockdown: subsystem {subsystem} gets fake LID."
                    )
                else:
                    self.logger.log(
                        f"[IdentityShadow] KillSwitch: subsystem {subsystem} gets fake LID."
                    )
                return self.state.fake_lid_numeric

            if self._temporal_cloak_active():
                temp_fake = self._generate_fake_lid()
                self.logger.log(
                    f"[IdentityShadow] Stealth-L5 Temporal Cloak: subsystem {subsystem} gets rotating fake LID."
                )
                return temp_fake

            if self.state.active and self.state.fake_lid_numeric is not None:
                return self.state.fake_lid_numeric

            self._log_leak(subsystem)
            if self.state.auto_kill:
                self.state.kill_switch = True
                self.logger.log(
                    f"[IdentityShadow] AutoKill: leak detected for subsystem [{subsystem}]. Kill Switch ACTIVATED."
                )
                self._persist_state()
                return self.state.fake_lid_numeric or self._generate_fake_lid()

            return self.state.real_lid_numeric or 0

    def _log_leak(self, subsystem: str):
        self.logger.log(
            f"[IdentityShadow] LeakDetector: potential real LID usage by subsystem [{subsystem}] "
            f"(Shadow OFF, KillSwitch OFF, Stealth tier={self.state.stealth_tier}, Lockdown OFF)."
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
                "stealth_tier": self.state.stealth_tier,
                "reboot_lockdown_until": self.state.reboot_lockdown_until,
                "last_rotation_ts": self.state.last_rotation_ts,
                "identity_null_decay_ts": self.state.identity_null_decay_ts,
                "leak_prediction_score": self.state.leak_prediction_score,
                "kill_switch_cooldown_until": self.state.kill_switch_cooldown_until,
            }


# ============================================================
# Pattern Detector + Threat Scores + Reputation
# ============================================================

@dataclass
class SubsystemStats:
    name: str
    access_count: int = 0
    last_access_ts: float = 0.0
    leak_count: int = 0
    flood_count: int = 0
    burst_count: int = 0
    last_burst_ts: float = 0.0


class PatternDetectorV3:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.subsystems: Dict[str, SubsystemStats] = {}
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("ml_patterns", {})
        try:
            for name, stats in data.items():
                self.subsystems[name] = SubsystemStats(
                    name=name,
                    access_count=stats.get("access_count", 0),
                    last_access_ts=stats.get("last_access_ts", 0.0),
                    leak_count=stats.get("leak_count", 0),
                    flood_count=stats.get("flood_count", 0),
                    burst_count=stats.get("burst_count", 0),
                    last_burst_ts=stats.get("last_burst_ts", 0.0),
                )
            self.logger.log(f"[PatternDetector] Loaded state for {len(self.subsystems)} subsystems.")
        except Exception as e:
            self.logger.log(f"[PatternDetector] Error loading pattern state: {e}")
            self.subsystems = {}

    def _persist_state(self):
        data = {
            name: {
                "access_count": stats.access_count,
                "last_access_ts": stats.last_access_ts,
                "leak_count": stats.leak_count,
                "flood_count": stats.flood_count,
                "burst_count": stats.burst_count,
                "last_burst_ts": stats.last_burst_ts,
            }
            for name, stats in self.subsystems.items()
        }
        self.state_store.set("ml_patterns", data)

    def record_access(self, subsystem: str):
        now = time.time()
        with self._lock:
            stats = self.subsystems.get(subsystem)
            if not stats:
                stats = SubsystemStats(name=subsystem)
                self.subsystems[subsystem] = stats
            stats.access_count += 1
            if now - stats.last_access_ts < 2.0:
                stats.burst_count += 1
                stats.last_burst_ts = now
            stats.last_access_ts = now
            self._persist_state()

    def record_leak(self, subsystem: str):
        with self._lock:
            stats = self.subsystems.get(subsystem)
            if not stats:
                stats = SubsystemStats(name=subsystem)
                self.subsystems[subsystem] = stats
            stats.leak_count += 1
            self._persist_state()

    def record_flood(self, subsystem: str):
        with self._lock:
            stats = self.subsystems.get(subsystem)
            if not stats:
                stats = SubsystemStats(name=subsystem)
                self.subsystems[subsystem] = stats
            stats.flood_count += 1
            self._persist_state()

    def compute_threat_score(self, subsystem: str) -> float:
        with self._lock:
            stats = self.subsystems.get(subsystem)
            if not stats:
                return 0.0
            score = (
                stats.leak_count * 5.0
                + stats.flood_count * 3.0
                + stats.burst_count * 2.0
                + stats.access_count * 0.5
            )
            return min(100.0, score)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            items = sorted(self.subsystems.items(), key=lambda x: x[1].access_count, reverse=True)[:8]
            return {
                name: {
                    "access_count": stats.access_count,
                    "leak_count": stats.leak_count,
                    "flood_count": stats.flood_count,
                    "burst_count": stats.burst_count,
                }
                for name, stats in items
            }


@dataclass
class SubsystemReputation:
    trust: float = 100.0
    risk: float = 0.0
    leak: float = 0.0
    behavior: float = 0.0


class ThreatScoreStore:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.scores: Dict[str, float] = {}
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("threat_scores", {})
        try:
            self.scores = {name: float(score) for name, score in data.items()}
            self.logger.log(f"[ThreatScores] Loaded {len(self.scores)} scores.")
        except Exception as e:
            self.logger.log(f"[ThreatScores] Error loading scores: {e}")
            self.scores = {}

    def _persist_state(self):
        self.state_store.set("threat_scores", self.scores)

    def set_score(self, subsystem: str, score: float):
        with self._lock:
            self.scores[subsystem] = float(score)
            self._persist_state()

    def get_score(self, subsystem: str) -> float:
        with self._lock:
            return self.scores.get(subsystem, 0.0)

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            items = sorted(self.scores.items(), key=lambda x: x[1], reverse=True)[:8]
            return dict(items)


class ReputationEngine:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.reputation: Dict[str, SubsystemReputation] = {}
        self._load()

    def _load(self):
        data = self.state_store.get("reputation", {})
        try:
            for name, rep in data.items():
                self.reputation[name] = SubsystemReputation(
                    trust=rep.get("trust", 100.0),
                    risk=rep.get("risk", 0.0),
                    leak=rep.get("leak", 0.0),
                    behavior=rep.get("behavior", 0.0),
                )
            self.logger.log(f"[Reputation] Loaded reputation for {len(self.reputation)} subsystems.")
        except Exception as e:
            self.logger.log(f"[Reputation] Error loading reputation: {e}")
            self.reputation = {}

    def _persist(self):
        data = {
            name: {
                "trust": rep.trust,
                "risk": rep.risk,
                "leak": rep.leak,
                "behavior": rep.behavior,
            }
            for name, rep in self.reputation.items()
        }
        self.state_store.set("reputation", data)

    def update_reputation(self, subsystem: str, threat_score: float, stats: SubsystemStats):
        with self._lock:
            rep = self.reputation.get(subsystem, SubsystemReputation())
            rep.risk = threat_score
            rep.leak = stats.leak_count * 5.0
            rep.behavior = stats.burst_count * 1.0 + stats.access_count * 0.2
            rep.trust = max(0.0, 100.0 - rep.risk - rep.leak - rep.behavior)
            self.reputation[subsystem] = rep
            self._persist()

    def get_reputation(self, subsystem: str) -> SubsystemReputation:
        with self._lock:
            return self.reputation.get(subsystem, SubsystemReputation())

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            items = sorted(self.reputation.items(), key=lambda x: x[1].risk, reverse=True)[:5]
            return {
                name: {
                    "trust": rep.trust,
                    "risk": rep.risk,
                    "leak": rep.leak,
                    "behavior": rep.behavior,
                }
                for name, rep in items
            }


# ============================================================
# Subsystem Quarantine v3
# ============================================================

class SubsystemQuarantine:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.quarantined: Dict[str, float] = {}
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("quarantine", {})
        try:
            self.quarantined = {name: float(ts) for name, ts in data.items()}
            self.logger.log(f"[Quarantine] Loaded {len(self.quarantined)} quarantined subsystems.")
        except Exception as e:
            self.logger.log(f"[Quarantine] Error loading quarantine state: {e}")
            self.quarantined = {}

    def _persist_state(self):
        self.state_store.set("quarantine", self.quarantined)

    def quarantine(self, subsystem: str):
        with self._lock:
            self.quarantined[subsystem] = time.time()
            self.logger.log(f"[Quarantine] Subsystem [{subsystem}] quarantined (fake-only identity).")
            self._persist_state()

    def is_quarantined(self, subsystem: str) -> bool:
        with self._lock:
            return subsystem in self.quarantined

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self.quarantined.items())[-5:]
            return dict(items)


# ============================================================
# Telemetry Mirage v4
# ============================================================

class TelemetryMirageV4:
    def __init__(self, logger: SafeLogger):
        self.logger = logger

    def generate_mirage_session(self, subsystem: str, persona: FakePersona, stream: bool = False):
        events = []
        base_ts = time.time()
        count = 5 if stream else 3
        for i in range(count):
            event_type = random.choice(
                ["browsing", "app_launch", "sync_failure", "health_change", "idle"]
            )
            payload = {
                "subsystem": subsystem,
                "persona_id": persona.id,
                "fingerprint": persona.device_fingerprint,
                "region": persona.metadata.get("region", "Unknown"),
                "event_type": event_type,
                "ts": base_ts + i * random.uniform(1.0, 8.0),
                "apps": persona.metadata.get("apps", []),
                "network_style": persona.metadata.get("network_style", "Unknown"),
                "usage_pattern": persona.metadata.get("usage_pattern", "Unknown"),
            }
            events.append(payload)
            self.logger.log(
                f"[MirageV4] Synthetic {event_type} event for [{subsystem}] persona [{persona.id}] (stream={stream})."
            )
        return events


# ============================================================
# Honeypot Sandbox
# ============================================================

class HoneypotSandbox:
    def __init__(self, logger: SafeLogger):
        self.logger = logger
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_event(self, event: Dict[str, Any]):
        with self._lock:
            self._events.append(event)
            if len(self._events) > 300:
                self._events = self._events[-300:]
        self.logger.log(f"[Honeypot] Recorded event: {event.get('type', 'unknown')}")

    def get_events(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            return self._events[-limit:]


# ============================================================
# NDIS Packet Engine (Simulated)
# ============================================================

@dataclass
class PacketFeature:
    subsystem: str
    size: int
    tag: str
    ts: float


class NDISPacketEngine:
    def __init__(self, logger: SafeLogger, event_bus: EventBus):
        self.logger = logger
        self.event_bus = event_bus
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.subsystem_tags = {
            "EdgeSync": "sync",
            "MicrosoftStore": "store",
            "Telemetry": "telemetry",
            "CloudSync": "sync",
            "VPN": "vpn",
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.log("[NDIS] Packet engine started.")

    def stop(self):
        self._running = False
        self.logger.log("[NDIS] Packet engine stopped.")

    def _loop(self):
        subsystems = list(self.subsystem_tags.keys())
        while self._running:
            time.sleep(random.uniform(0.5, 2.0))
            subsystem = random.choice(subsystems)
            tag = self.subsystem_tags.get(subsystem, "unknown")
            size = random.randint(64, 1500)
            pf = PacketFeature(subsystem=subsystem, size=size, tag=tag, ts=time.time())
            self.logger.log(f"[NDIS] Synthetic packet: {subsystem} tag={tag} size={size}")
            self.event_bus.publish(Event(type="packet_feature", payload={"packet": pf.__dict__}))


# ============================================================
# Suricata v7 (Simulated Rule Engine)
# ============================================================

@dataclass
class SuricataRule:
    id: str
    category: str
    priority: int
    tag: str
    min_size: int
    max_size: int
    base_score: float


class SuricataEngineV7:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.rules: List[SuricataRule] = []
        self._load_rules()

    def _load_rules(self):
        data = self.state_store.get("suricata_rules", None)
        if data:
            try:
                self.rules = [
                    SuricataRule(
                        id=r["id"],
                        category=r["category"],
                        priority=r["priority"],
                        tag=r["tag"],
                        min_size=r["min_size"],
                        max_size=r["max_size"],
                        base_score=r["base_score"],
                    )
                    for r in data
                ]
                self.logger.log(f"[SuricataV7] Loaded {len(self.rules)} rules from state.")
            except Exception as e:
                self.logger.log(f"[SuricataV7] Error loading rules: {e}")
                self.rules = []
        if not self.rules:
            self._init_default_rules()
            self._persist_rules()

    def _init_default_rules(self):
        self.rules = [
            SuricataRule("R1", "sync", 1, "sync", 200, 1500, 15.0),
            SuricataRule("R2", "telemetry", 2, "telemetry", 100, 1200, 10.0),
            SuricataRule("R3", "store", 2, "store", 150, 1400, 12.0),
            SuricataRule("R4", "vpn", 1, "vpn", 64, 1500, 18.0),
            SuricataRule("R5", "unknown", 3, "unknown", 64, 1500, 8.0),
        ]
        self.logger.log("[SuricataV7] Initialized default rules.")

    def _persist_rules(self):
        data = [
            {
                "id": r.id,
                "category": r.category,
                "priority": r.priority,
                "tag": r.tag,
                "min_size": r.min_size,
                "max_size": r.max_size,
                "base_score": r.base_score,
            }
            for r in self.rules
        ]
        self.state_store.set("suricata_rules", data)

    def evaluate_packet(self, packet: PacketFeature) -> float:
        score = 0.0
        with self._lock:
            for rule in self.rules:
                if rule.tag == packet.tag and rule.min_size <= packet.size <= rule.max_size:
                    score += rule.base_score * (1.0 + rule.priority * 0.1)
        if score > 0.0:
            self.logger.log(
                f"[SuricataV7] Packet {packet.subsystem} tag={packet.tag} size={packet.size} -> score={score:.1f}"
            )
        return score

    def learn_rule(self, packet: PacketFeature, threat_score: float):
        if threat_score < 40.0:
            return
        with self._lock:
            rule_id = f"LR-{random.randint(1000,9999)}"
            new_rule = SuricataRule(
                id=rule_id,
                category="learned",
                priority=2,
                tag=packet.tag,
                min_size=max(64, packet.size - 200),
                max_size=min(1500, packet.size + 200),
                base_score=min(25.0, threat_score * 0.3),
            )
            self.rules.append(new_rule)
            self.logger.log(
                f"[SuricataV7] Learned new rule {rule_id} for tag={packet.tag} size~{packet.size} threat={threat_score:.1f}"
            )
            self._persist_rules()


# ============================================================
# GPU Inference v2 (Simulated)
# ============================================================

class GPUInferenceV2:
    def __init__(self, logger: SafeLogger):
        self.logger = logger

    def compute_threat_boost(
        self,
        packet: PacketFeature,
        persona: FakePersona,
        shadow_snapshot: Dict[str, Any],
        cluster_threat: float,
        quarantined: bool,
    ) -> float:
        base = packet.size / 1500.0 * 20.0
        risk_factor = 10.0 if persona.risk_level == "high" else 5.0 if persona.risk_level == "medium" else 2.0
        stealth_factor = shadow_snapshot.get("stealth_tier", 0) * 2.0
        cluster_factor = cluster_threat * 0.2
        quarantine_factor = 10.0 if quarantined else 0.0
        boost = base + risk_factor + stealth_factor + cluster_factor + quarantine_factor
        boost = min(40.0, boost)
        self.logger.log(
            f"[GPUv2] Threat boost: base={base:.1f} risk={risk_factor:.1f} stealth={stealth_factor:.1f} "
            f"cluster={cluster_factor:.1f} quarantine={quarantine_factor:.1f} -> {boost:.1f}"
        )
        return boost


# ============================================================
# Raft/Paxos Mesh v2 (Simulated)
# ============================================================

@dataclass
class MeshNodeState:
    id: str
    threat_view: float
    alive: bool = True


class MeshClusterV2:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.nodes: Dict[str, MeshNodeState] = {}
        self.leader_id: Optional[str] = None
        self._load_state()

    def _load_state(self):
        data = self.state_store.get("mesh_state", None)
        if data:
            try:
                self.nodes = {
                    nid: MeshNodeState(
                        id=nid,
                        threat_view=node.get("threat_view", 0.0),
                        alive=node.get("alive", True),
                    )
                    for nid, node in data.get("nodes", {}).items()
                }
                self.leader_id = data.get("leader_id", None)
                self.logger.log(f"[MeshCluster] Loaded {len(self.nodes)} nodes, leader={self.leader_id}.")
            except Exception as e:
                self.logger.log(f"[MeshCluster] Error loading mesh state: {e}")
                self._init_default()
        else:
            self._init_default()

    def _init_default(self):
        self.nodes = {
            "node-A": MeshNodeState("node-A", 0.0),
            "node-B": MeshNodeState("node-B", 0.0),
            "node-C": MeshNodeState("node-C", 0.0),
        }
        self.leader_id = "node-A"
        self._persist_state()
        self.logger.log("[MeshCluster] Initialized default 3-node cluster.")

    def _persist_state(self):
        data = {
            "nodes": {
                nid: {"threat_view": node.threat_view, "alive": node.alive}
                for nid, node in self.nodes.items()
            },
            "leader_id": self.leader_id,
        }
        self.state_store.set("mesh_state", data)

    def update_threat_view(self, global_threat: float):
        with self._lock:
            for node in self.nodes.values():
                if node.alive:
                    jitter = random.uniform(-5.0, 5.0)
                    node.threat_view = max(0.0, min(100.0, global_threat + jitter))
            self._elect_leader()
            self._persist_state()
            self.logger.log(
                f"[MeshCluster] Updated threat views; leader={self.leader_id} global={global_threat:.1f}"
            )

    def _elect_leader(self):
        alive_nodes = [n for n in self.nodes.values() if n.alive]
        if not alive_nodes:
            self.leader_id = None
            return
        self.leader_id = max(alive_nodes, key=lambda n: n.threat_view).id

    def simulate_split_brain(self):
        with self._lock:
            if random.random() < 0.2:
                node = random.choice(list(self.nodes.values()))
                node.alive = False
                self.logger.log(f"[MeshCluster] Simulated node failure: {node.id}")
                self._persist_state()

    def heal_cluster(self):
        with self._lock:
            for node in self.nodes.values():
                node.alive = True
            self._elect_leader()
            self._persist_state()
            self.logger.log("[MeshCluster] Cluster healed; all nodes alive.")

    def get_cluster_threat(self) -> float:
        with self._lock:
            alive_nodes = [n for n in self.nodes.values() if n.alive]
            if not alive_nodes:
                return 0.0
            return sum(n.threat_view for n in alive_nodes) / len(alive_nodes)


# ============================================================
# Threat Matrix v2
# ============================================================

class ThreatMatrixV2:
    def __init__(self, state_store: JsonStateStoreV3, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.matrix: Dict[str, str] = {}
        self._load()

    def _load(self):
        data = self.state_store.get("threat_matrix", {})
        self.matrix = dict(data)
        self.logger.log(f"[ThreatMatrix] Loaded {len(self.matrix)} entries.")

    def _persist(self):
        self.state_store.set("threat_matrix", self.matrix)

    def classify(self, subsystem: str, threat_score: float, rep: SubsystemReputation, cluster_threat: float):
        glyph = "●"
        if threat_score >= 80 or rep.risk >= 80:
            glyph = "☠"
        elif threat_score >= 60 or rep.risk >= 60:
            glyph = "✖"
        elif threat_score >= 40 or rep.risk >= 40:
            glyph = "⚠"
        elif threat_score >= 20 or rep.risk >= 20:
            glyph = "△"
        else:
            glyph = "●"

        if cluster_threat > 70:
            glyph = "⧈"  # anomaly / cluster instability

        with self._lock:
            self.matrix[subsystem] = glyph
            self._persist()
        self.logger.log(
            f"[ThreatMatrix] Subsystem [{subsystem}] classified as {glyph} (score={threat_score:.1f}, cluster={cluster_threat:.1f})"
        )

    def get_snapshot(self) -> Dict[str, str]:
        with self._lock:
            return dict(self.matrix)


# ============================================================
# Fake Telemetry Engine v4
# ============================================================

class FakeTelemetryEngineV4:
    def __init__(
        self,
        persona_engine: PersonaEngineV4,
        identity_shadow: IdentityShadowLayerV4,
        logger: SafeLogger,
        pattern_detector: PatternDetectorV3,
        quarantine: SubsystemQuarantine,
        mirage: TelemetryMirageV4,
        honeypot: HoneypotSandbox,
        event_bus: EventBus,
    ):
        self.persona_engine = persona_engine
        self.identity_shadow = identity_shadow
        self.logger = logger
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.mirage = mirage
        self.honeypot = honeypot
        self.event_bus = event_bus
        self._lock = threading.Lock()
        self._event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.flooder_enabled: bool = False
        self.telemetry_counter: int = 0

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True)
                self._thread.start()
                self.logger.log("[TelemetryV4] Engine started.")

    def stop(self):
        with self._lock:
            self._running = False
        self.logger.log("[TelemetryV4] Engine stopped.")

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

        self.pattern_detector.record_access(subsystem)

        event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona": {
                "id": persona.id,
                "device_fingerprint": persona.device_fingerprint,
                "activity_profile": persona.activity_profile,
                "sync_state": persona.sync_state,
                "risk_level": persona.risk_level,
                "metadata": persona.metadata,
            },
            "effective_lid": effective_lid,
            "shadow_snapshot": snapshot,
            "ts": time.time(),
        }
        self._event_queue.put(event)

    def toggle_flooder(self):
        with self._lock:
            self.flooder_enabled = not self.flooder_enabled
            state = "ACTIVE" if self.flooder_enabled else "INACTIVE"
            self.logger.log(f"[TelemetryV4] Flooder toggled: {state}")

    def _process_event(self, event: Dict[str, Any]):
        if event["type"] == "identity_access":
            self._handle_identity_access(event)

    def _glyph_for_state(self, snapshot: Dict[str, Any]) -> str:
        stealth_mode = snapshot["stealth_mode"]
        stealth_tier = snapshot["stealth_tier"]
        kill_switch = snapshot["kill_switch"]
        active = snapshot["active"]
        lockdown = time.time() < snapshot["reboot_lockdown_until"]

        if stealth_mode:
            if stealth_tier == 6:
                return "⬛"
            if stealth_tier == 5:
                return "▤"
            if stealth_tier == 4:
                return "▣"
            if stealth_tier == 3:
                return "□"
            if stealth_tier == 2:
                return "◻"
            return "◽"
        if kill_switch or lockdown:
            return "■"
        if active:
            return "●"
        return "▲"

    def _handle_identity_access(self, event: Dict[str, Any]):
        persona_data = event["persona"]
        persona = FakePersona(
            id=persona_data["id"],
            device_fingerprint=persona_data["device_fingerprint"],
            activity_profile=persona_data["activity_profile"],
            sync_state=persona_data["sync_state"],
            risk_level=persona_data["risk_level"],
            metadata=persona_data["metadata"],
            memory=[],
        )

        lid = event["effective_lid"]
        snapshot = event["shadow_snapshot"]
        subsystem = event["subsystem"]

        glyph = self._glyph_for_state(snapshot)
        mode_tags = []
        if snapshot["kill_switch"]:
            mode_tags.append("KillSwitch")
        if snapshot["active"]:
            mode_tags.append("Shadow")
        if snapshot["auto_kill"]:
            mode_tags.append("AutoKill")
        if snapshot["stealth_mode"]:
            mode_tags.append(f"Stealth-L{snapshot['stealth_tier']}")
        if self.flooder_enabled:
            mode_tags.append("Flooder")
        if self.persona_engine.get_swarm_state():
            mode_tags.append("Swarm")
        if self.quarantine.is_quarantined(subsystem):
            mode_tags.append("Quarantined")

        tag_str = ",".join(mode_tags) if mode_tags else "Normal"

        msg = (
            f"{glyph} Identity access by [{subsystem}] -> "
            f"LID={lid} modes=[{tag_str}] "
            f"persona={persona.id} fp={persona.device_fingerprint} "
            f"activity={persona.activity_profile} sync={persona.sync_state} "
            f"risk={persona.risk_level}"
        )
        self.logger.log(msg)

        events = self.mirage.generate_mirage_session(subsystem, persona, stream=True)
        for e in events:
            self.persona_engine.add_memory_event(
                persona,
                event_type=e["event_type"],
                details={"subsystem": subsystem, "ts": e["ts"]},
            )

        honeypot_event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona_id": persona.id,
            "ts": time.time(),
        }
        self.honeypot.record_event(honeypot_event)

        self.telemetry_counter += 1
        if self.flooder_enabled:
            self._identity_flood(subsystem)

        self.event_bus.publish(Event(type="identity_access_event", payload={"subsystem": subsystem}))

    def _identity_flood(self, subsystem: str):
        burst_size = random.randint(2, 4)
        for i in range(burst_size):
            persona = self.persona_engine.get_persona(f"{subsystem}-Flood-{i}")
            fake_lid = random.getrandbits(64)
            glyph = "◆"
            msg = (
                f"{glyph} Flood v2 event [{i}/{burst_size}] for subsystem [{subsystem}] -> "
                f"LID={fake_lid} persona={persona.id} fp={persona.device_fingerprint} "
                f"activity={persona.activity_profile} sync={persona.sync_state} "
                f"risk={persona.risk_level}"
            )
            self.logger.log(msg)
            self.pattern_detector.record_flood(subsystem)
            self.event_bus.publish(Event(type="telemetry_flood_event", payload={"subsystem": subsystem}))


# ============================================================
# Self-Healing Engine v2
# ============================================================

class SelfHealingEngineV2:
    def __init__(
        self,
        logger: SafeLogger,
        state_store: JsonStateStoreV3,
        identity_shadow: IdentityShadowLayerV4,
        persona_engine: PersonaEngineV4,
        pattern_detector: PatternDetectorV3,
        quarantine: SubsystemQuarantine,
        threat_scores: ThreatScoreStore,
        reputation_engine: ReputationEngine,
        mesh_cluster: MeshClusterV2,
    ):
        self.logger = logger
        self.state_store = state_store
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.threat_scores = threat_scores
        self.reputation_engine = reputation_engine
        self.mesh_cluster = mesh_cluster
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._running = True
        self._thread.start()

    def _loop(self):
        while self._running:
            time.sleep(15)
            self._check_and_heal()

    def stop(self):
        self._running = False

    def _check_and_heal(self):
        with self._lock:
            shadow_data = self.state_store.get("identity_shadow", None)
            if not shadow_data:
                self.logger.log("[SelfHealingV2] Missing identity_shadow state. Reinitializing.")
                self.identity_shadow._init_state()
                self.identity_shadow._persist_state()

            persona_data = self.state_store.get("persona", None)
            if not persona_data:
                self.logger.log("[SelfHealingV2] Missing persona state. Regenerating.")
                self.persona_engine.rotate_persona(reason="self-heal")

            swarm_data = self.state_store.get("persona_swarm", None)
            if self.persona_engine.get_swarm_state() and not swarm_data:
                self.logger.log("[SelfHealingV2] Swarm enabled but no swarm state. Rebuilding swarm.")
                self.persona_engine.toggle_swarm()

            patterns_data = self.state_store.get("ml_patterns", None)
            if patterns_data is None:
                self.logger.log("[SelfHealingV2] Missing pattern state. Resetting.")
                self.state_store.set("ml_patterns", {})

            quarantine_data = self.state_store.get("quarantine", None)
            if quarantine_data is None:
                self.logger.log("[SelfHealingV2] Missing quarantine state. Resetting.")
                self.state_store.set("quarantine", {})

            threat_data = self.state_store.get("threat_scores", None)
            if threat_data is None:
                self.logger.log("[SelfHealingV2] Missing threat_scores state. Resetting.")
                self.state_store.set("threat_scores", {})

            reputation_data = self.state_store.get("reputation", None)
            if reputation_data is None:
                self.logger.log("[SelfHealingV2] Missing reputation state. Resetting.")
                self.state_store.set("reputation", {})

            mesh_data = self.state_store.get("mesh_state", None)
            if mesh_data is None:
                self.logger.log("[SelfHealingV2] Missing mesh_state. Reinitializing cluster.")
                self.mesh_cluster._init_default()


# ============================================================
# Agentic Core + Policy Engine
# ============================================================

class PolicyEngineV2:
    def __init__(self, logger: SafeLogger):
        self.logger = logger

    def apply_policies(
        self,
        subsystem: str,
        threat_score: float,
        rep: SubsystemReputation,
        cluster_threat: float,
        identity_shadow: IdentityShadowLayerV4,
        persona_engine: PersonaEngineV4,
        quarantine: SubsystemQuarantine,
        telemetry_engine: FakeTelemetryEngineV4,
    ):
        if threat_score >= 25.0 and not quarantine.is_quarantined(subsystem):
            quarantine.quarantine(subsystem)

        if telemetry_engine.telemetry_counter >= 40:
            self.logger.log("[PolicyEngine] Telemetry spike -> Stealth tier 2.")
            identity_shadow.set_stealth_tier(2)
            telemetry_engine.telemetry_counter = 0

        if threat_score >= 40.0:
            if not persona_engine.get_swarm_state():
                self.logger.log("[PolicyEngine] High threat -> enable swarm.")
                persona_engine.toggle_swarm()

        if "Sync" in subsystem or "Cloud" in subsystem:
            self.logger.log("[PolicyEngine] Sync-like subsystem -> Kill Switch.")
            identity_shadow.toggle_kill_switch()

        if threat_score >= 60.0 or rep.risk >= 60.0:
            self.logger.log("[PolicyEngine] Very high threat -> Stealth tier 3 + Flooder.")
            identity_shadow.set_stealth_tier(3)
            if not telemetry_engine.flooder_enabled:
                telemetry_engine.toggle_flooder()

        if rep.risk >= 80.0 or cluster_threat >= 80.0:
            self.logger.log("[PolicyEngine] Extreme risk -> Stealth-L4 cloak.")
            identity_shadow.set_stealth_tier(4)

        if cluster_threat >= 90.0:
            self.logger.log("[PolicyEngine] Cluster instability -> Stealth-L5 temporal cloak.")
            identity_shadow.set_stealth_tier(5)


class AgenticCoreV1:
    def __init__(
        self,
        logger: SafeLogger,
        event_bus: EventBus,
        pattern_detector: PatternDetectorV3,
        threat_scores: ThreatScoreStore,
        reputation_engine: ReputationEngine,
        identity_shadow: IdentityShadowLayerV4,
        persona_engine: PersonaEngineV4,
        quarantine: SubsystemQuarantine,
        mesh_cluster: MeshClusterV2,
        threat_matrix: ThreatMatrixV2,
        gpu_inference: GPUInferenceV2,
        suricata: SuricataEngineV7,
        telemetry_engine: FakeTelemetryEngineV4,
    ):
        self.logger = logger
        self.event_bus = event_bus
        self.pattern_detector = pattern_detector
        self.threat_scores = threat_scores
        self.reputation_engine = reputation_engine
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.quarantine = quarantine
        self.mesh_cluster = mesh_cluster
        self.threat_matrix = threat_matrix
        self.gpu_inference = gpu_inference
        self.suricata = suricata
        self.telemetry_engine = telemetry_engine
        self.policy_engine = PolicyEngineV2(logger)

        self.event_bus.subscribe("packet_feature", self._on_packet_feature)
        self.event_bus.subscribe("identity_access_event", self._on_identity_access_event)
        self.event_bus.subscribe("telemetry_flood_event", self._on_telemetry_flood_event)

    def _on_packet_feature(self, event: Event):
        packet_data = event.payload["packet"]
        packet = PacketFeature(
            subsystem=packet_data["subsystem"],
            size=packet_data["size"],
            tag=packet_data["tag"],
            ts=packet_data["ts"],
        )
        suricata_score = self.suricata.evaluate_packet(packet)
        persona = self.persona_engine.get_persona(packet.subsystem)
        shadow_snapshot = self.identity_shadow.get_state_snapshot()
        cluster_threat = self.mesh_cluster.get_cluster_threat()
        quarantined = self.quarantine.is_quarantined(packet.subsystem)
        gpu_boost = self.gpu_inference.compute_threat_boost(
            packet, persona, shadow_snapshot, cluster_threat, quarantined
        )

        base_score = self.pattern_detector.compute_threat_score(packet.subsystem)
        total_score = min(100.0, base_score + suricata_score + gpu_boost)
        self.threat_scores.set_score(packet.subsystem, total_score)

        stats_snapshot = self.pattern_detector.get_snapshot().get(packet.subsystem, {})
        stats = SubsystemStats(
            name=packet.subsystem,
            access_count=stats_snapshot.get("access_count", 0),
            leak_count=stats_snapshot.get("leak_count", 0),
            flood_count=stats_snapshot.get("flood_count", 0),
            burst_count=stats_snapshot.get("burst_count", 0),
        )
        self.reputation_engine.update_reputation(packet.subsystem, total_score, stats)
        rep = self.reputation_engine.get_reputation(packet.subsystem)

        self.identity_shadow.update_leak_prediction(stats.leak_count, stats.burst_count)

        self.mesh_cluster.update_threat_view(total_score)
        cluster_threat = self.mesh_cluster.get_cluster_threat()

        self.threat_matrix.classify(packet.subsystem, total_score, rep, cluster_threat)

        self.policy_engine.apply_policies(
            packet.subsystem,
            total_score,
            rep,
            cluster_threat,
            self.identity_shadow,
            self.persona_engine,
            self.quarantine,
            self.telemetry_engine,
        )

        self.persona_engine.evolve_current_persona(total_score, cluster_threat, reason="packet-driven")

    def _on_identity_access_event(self, event: Event):
        subsystem = event.payload["subsystem"]
        score = self.threat_scores.get_score(subsystem)
        rep = self.reputation_engine.get_reputation(subsystem)
        cluster_threat = self.mesh_cluster.get_cluster_threat()
        self.policy_engine.apply_policies(
            subsystem,
            score,
            rep,
            cluster_threat,
            self.identity_shadow,
            self.persona_engine,
            self.quarantine,
            self.telemetry_engine,
        )

    def _on_telemetry_flood_event(self, event: Event):
        subsystem = event.payload["subsystem"]
        self.logger.log(f"[AgenticCore] Telemetry flood event from [{subsystem}] observed.")


# ============================================================
# Qt GUI – Optional, Freeze-Proof
# ============================================================

class CodexQtGUI(QtWidgets.QMainWindow):
    def __init__(
        self,
        logger: SafeLogger,
        identity_shadow: IdentityShadowLayerV4,
        persona_engine: PersonaEngineV4,
        telemetry_engine: FakeTelemetryEngineV4,
        pattern_detector: PatternDetectorV3,
        quarantine: SubsystemQuarantine,
        threat_scores: ThreatScoreStore,
        reputation_engine: ReputationEngine,
        threat_matrix: ThreatMatrixV2,
    ):
        super().__init__()
        self.logger = logger
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.telemetry_engine = telemetry_engine
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.threat_scores = threat_scores
        self.reputation_engine = reputation_engine
        self.threat_matrix = threat_matrix

        self.setWindowTitle("Codex Purge Shell – v11 (Agentic, Freeze-Proof GUI)")
        self.resize(1350, 820)

        self.lite_mode: bool = True

        self._build_ui()

        self.refresh_timer = QtCore.QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_ui)
        self.refresh_timer.start(5000)

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)

        # Shadow Panel
        shadow_group = QtWidgets.QGroupBox("Identity Shadow Layer v4")
        layout.addWidget(shadow_group)
        s_layout = QtWidgets.QGridLayout(shadow_group)

        self.shadow_status_label = QtWidgets.QLabel("Shadow Status: Unknown")
        s_layout.addWidget(self.shadow_status_label, 0, 0)

        self.shadow_toggle_btn = QtWidgets.QPushButton("Toggle Shadow ON/OFF")
        self.shadow_toggle_btn.clicked.connect(self._toggle_shadow)
        s_layout.addWidget(self.shadow_toggle_btn, 0, 1)

        self.kill_switch_label = QtWidgets.QLabel("Kill Switch: Unknown")
        s_layout.addWidget(self.kill_switch_label, 1, 0)

        self.kill_switch_btn = QtWidgets.QPushButton("Toggle Kill Switch")
        self.kill_switch_btn.clicked.connect(self._toggle_kill_switch)
        s_layout.addWidget(self.kill_switch_btn, 1, 1)

        self.auto_kill_label = QtWidgets.QLabel("Auto-Kill: Unknown")
        s_layout.addWidget(self.auto_kill_label, 2, 0)

        self.auto_kill_btn = QtWidgets.QPushButton("Toggle Auto-Kill")
        self.auto_kill_btn.clicked.connect(self._toggle_auto_kill)
        s_layout.addWidget(self.auto_kill_btn, 2, 1)

        self.stealth_label = QtWidgets.QLabel("Stealth Mode: Unknown")
        s_layout.addWidget(self.stealth_label, 3, 0)

        self.stealth_btn = QtWidgets.QPushButton("Toggle Stealth Mode")
        self.stealth_btn.clicked.connect(self._toggle_stealth)
        s_layout.addWidget(self.stealth_btn, 3, 1)

        self.stealth_tier_label = QtWidgets.QLabel("Stealth Tier: Unknown")
        s_layout.addWidget(self.stealth_tier_label, 4, 0)

        tier_buttons_layout = QtWidgets.QHBoxLayout()
        for tier, label in [
            (1, "Tier 1"),
            (2, "Tier 2"),
            (3, "Tier 3"),
            (4, "Tier 4 (Cloak)"),
            (5, "Tier 5 (Temporal)"),
            (6, "Tier 6 (Quantum Null)"),
        ]:
            btn = QtWidgets.QPushButton(label)
            btn.clicked.connect(lambda _, t=tier: self._set_stealth_tier(t))
            tier_buttons_layout.addWidget(btn)
        s_layout.addLayout(tier_buttons_layout, 4, 1)

        self.rotate_lid_btn = QtWidgets.QPushButton("Rotate Fake LID Now")
        self.rotate_lid_btn.clicked.connect(self._rotate_fake_lid)
        s_layout.addWidget(self.rotate_lid_btn, 0, 2)

        self.shadow_summary = QtWidgets.QPlainTextEdit()
        self.shadow_summary.setReadOnly(True)
        self.shadow_summary.setMaximumHeight(140)
        s_layout.addWidget(self.shadow_summary, 5, 0, 1, 3)

        # Persona Panel
        persona_group = QtWidgets.QGroupBox("Fake Persona Metadata v4 (Summary)")
        layout.addWidget(persona_group)
        p_layout = QtWidgets.QGridLayout(persona_group)

        self.persona_summary = QtWidgets.QPlainTextEdit()
        self.persona_summary.setReadOnly(True)
        self.persona_summary.setMaximumHeight(160)
        p_layout.addWidget(self.persona_summary, 0, 0, 1, 3)

        self.rotate_persona_btn = QtWidgets.QPushButton("Rotate Persona")
        self.rotate_persona_btn.clicked.connect(self._rotate_persona)
        p_layout.addWidget(self.rotate_persona_btn, 1, 0)

        self.persona_lock_label = QtWidgets.QLabel("Persona Lock: Unknown")
        p_layout.addWidget(self.persona_lock_label, 1, 1)

        self.persona_lock_btn = QtWidgets.QPushButton("Toggle Persona Lock")
        self.persona_lock_btn.clicked.connect(self._toggle_persona_lock)
        p_layout.addWidget(self.persona_lock_btn, 1, 2)

        self.swarm_label = QtWidgets.QLabel("Persona Swarm: Unknown")
        p_layout.addWidget(self.swarm_label, 2, 0)

        self.swarm_btn = QtWidgets.QPushButton("Toggle Persona Swarm")
        self.swarm_btn.clicked.connect(self._toggle_swarm)
        p_layout.addWidget(self.swarm_btn, 2, 1)

        self.swarm_summary = QtWidgets.QPlainTextEdit()
        self.swarm_summary.setReadOnly(True)
        self.swarm_summary.setMaximumHeight(120)
        p_layout.addWidget(self.swarm_summary, 3, 0, 1, 3)

        # Telemetry Panel
        telemetry_group = QtWidgets.QGroupBox("Identity Access Log (Glyph-coded v4, Lite)")
        layout.addWidget(telemetry_group)
        t_layout = QtWidgets.QVBoxLayout(telemetry_group)

        self.telemetry_log = QtWidgets.QPlainTextEdit()
        self.telemetry_log.setReadOnly(True)
        t_layout.addWidget(self.telemetry_log)

        btn_row = QtWidgets.QHBoxLayout()
        self.sim_access_edge = QtWidgets.QPushButton("Simulate Identity Access (Edge Sync)")
        self.sim_access_edge.clicked.connect(lambda: self._simulate_identity_access("EdgeSync"))
        btn_row.addWidget(self.sim_access_edge)

        self.sim_access_store = QtWidgets.QPushButton("Simulate Identity Access (Store)")
        self.sim_access_store.clicked.connect(lambda: self._simulate_identity_access("MicrosoftStore"))
        btn_row.addWidget(self.sim_access_store)

        self.sim_access_telemetry = QtWidgets.QPushButton("Simulate Identity Access (Telemetry)")
        self.sim_access_telemetry.clicked.connect(lambda: self._simulate_identity_access("Telemetry"))
        btn_row.addWidget(self.sim_access_telemetry)

        self.refresh_log_btn = QtWidgets.QPushButton("Refresh Log")
        self.refresh_log_btn.clicked.connect(self._refresh_log)
        btn_row.addWidget(self.refresh_log_btn)

        t_layout.addLayout(btn_row)

        status_row = QtWidgets.QHBoxLayout()
        self.flooder_label = QtWidgets.QLabel("Identity Flooder v2: Unknown")
        status_row.addWidget(self.flooder_label)

        self.flooder_btn = QtWidgets.QPushButton("Toggle Flooder v2")
        self.flooder_btn.clicked.connect(self._toggle_flooder)
        status_row.addWidget(self.flooder_btn)

        self.logger_mode_label = QtWidgets.QLabel("Logger Mode: Normal")
        status_row.addWidget(self.logger_mode_label)

        self.logger_mode_btn = QtWidgets.QPushButton("Toggle Low-Noise")
        self.logger_mode_btn.clicked.connect(self._toggle_logger_mode)
        status_row.addWidget(self.logger_mode_btn)

        self.lite_mode_label = QtWidgets.QLabel("GUI Mode: Lite (Freeze-Proof)")
        status_row.addWidget(self.lite_mode_label)

        self.lite_mode_btn = QtWidgets.QPushButton("Toggle Lite/Heavy GUI")
        self.lite_mode_btn.clicked.connect(self._toggle_lite_mode)
        status_row.addWidget(self.lite_mode_btn)

        t_layout.addLayout(status_row)

        # Patterns / Quarantine / Threat / Reputation / Matrix Panel
        meta_group = QtWidgets.QGroupBox("Patterns, Quarantine, Threat Scores, Reputation, Matrix (Summaries)")
        layout.addWidget(meta_group)
        m_layout = QtWidgets.QGridLayout(meta_group)

        self.pattern_view = QtWidgets.QPlainTextEdit()
        self.pattern_view.setReadOnly(True)
        self.pattern_view.setMaximumHeight(100)
        m_layout.addWidget(self.pattern_view, 0, 0, 1, 2)

        self.quarantine_view = QtWidgets.QPlainTextEdit()
        self.quarantine_view.setReadOnly(True)
        self.quarantine_view.setMaximumHeight(70)
        m_layout.addWidget(self.quarantine_view, 1, 0, 1, 2)

        self.threat_view = QtWidgets.QPlainTextEdit()
        self.threat_view.setReadOnly(True)
        self.threat_view.setMaximumHeight(70)
        m_layout.addWidget(self.threat_view, 2, 0, 1, 2)

        self.reputation_view = QtWidgets.QPlainTextEdit()
        self.reputation_view.setReadOnly(True)
        self.reputation_view.setMaximumHeight(70)
        m_layout.addWidget(self.reputation_view, 3, 0, 1, 2)

        self.matrix_view = QtWidgets.QPlainTextEdit()
        self.matrix_view.setReadOnly(True)
        self.matrix_view.setMaximumHeight(70)
        m_layout.addWidget(self.matrix_view, 4, 0, 1, 2)

        # Glyph Legend
        legend_group = QtWidgets.QGroupBox("Glyph Legend v4")
        layout.addWidget(legend_group)
        l_layout = QtWidgets.QVBoxLayout(legend_group)

        legend_text = (
            "■ Kill Switch / Lockdown ACTIVE – hard block, real identity never leaves.\n"
            "● Shadow ACTIVE – fake identity used, real identity shadowed.\n"
            "▲ Shadow OFF & Kill Switch OFF – potential leak, Leak Detector watching.\n"
            "◽ Stealth-L1 – light stealth, fake identity bias.\n"
            "◻ Stealth-L2 – strong stealth, identity-null bias.\n"
            "□ Stealth-L3 – maximum stealth, identity-null enforced.\n"
            "▣ Stealth-L4 – identity-void cloak, machine appears identity-null.\n"
            "▤ Stealth-L5 – temporal cloak, identity rotates per request.\n"
            "⬛ Stealth-L6 – quantum null, identity undefined.\n"
            "◆ Flood v2 – Identity Flooder generating burst fake identity noise.\n"
            "☠ Extreme threat, ✖ High, ⚠ Medium, △ Low, ● Normal, ⧈ Cluster anomaly."
        )
        self.legend_label = QtWidgets.QLabel(legend_text)
        self.legend_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        l_layout.addWidget(self.legend_label)

    # --- Callbacks ---

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

    def _set_stealth_tier(self, tier: int):
        self.identity_shadow.set_stealth_tier(tier)
        self._refresh_ui()

    def _rotate_fake_lid(self):
        self.identity_shadow.rotate_fake_lid()
        self._refresh_ui()

    def _rotate_persona(self):
        self.persona_engine.rotate_persona(reason="manual")
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

    def _toggle_logger_mode(self):
        new_mode = not logger.low_noise_mode
        logger.set_low_noise(new_mode)
        self._refresh_ui()

    def _toggle_lite_mode(self):
        self.lite_mode = not self.lite_mode
        mode = "Lite (Freeze-Proof)" if self.lite_mode else "Heavy (Verbose)"
        self.lite_mode_label.setText(f"GUI Mode: {mode}")
        self._refresh_ui()

    def _simulate_identity_access(self, subsystem: str):
        self.telemetry_engine.submit_identity_access(subsystem)

    # --- Refresh ---

    def _refresh_ui(self):
        snapshot = self.identity_shadow.get_state_snapshot()
        status = "ACTIVE" if snapshot["active"] else "INACTIVE"
        kill_state = "ACTIVE" if snapshot["kill_switch"] else "INACTIVE"
        auto_kill_state = "ACTIVE" if snapshot["auto_kill"] else "INACTIVE"
        stealth_state = "ACTIVE" if snapshot["stealth_mode"] else "INACTIVE"
        stealth_tier = snapshot["stealth_tier"]

        glyph = "●" if snapshot["active"] else "▲"
        if snapshot["kill_switch"] or time.time() < snapshot["reboot_lockdown_until"]:
            glyph = "■"
        if snapshot["stealth_mode"]:
            if stealth_tier == 6:
                glyph = "⬛"
            elif stealth_tier == 5:
                glyph = "▤"
            elif stealth_tier == 4:
                glyph = "▣"
            elif stealth_tier == 3:
                glyph = "□"
            elif stealth_tier == 2:
                glyph = "◻"
            else:
                glyph = "◽"

        self.shadow_status_label.setText(f"Shadow Status: {status} {glyph}")
        self.kill_switch_label.setText(f"Kill Switch: {kill_state} ■")
        self.auto_kill_label.setText(f"Auto-Kill: {auto_kill_state}")
        self.stealth_label.setText(f"Stealth Mode: {stealth_state}")
        self.stealth_tier_label.setText(f"Stealth Tier: {stealth_tier}")

        shadow_summary = {
            "active": snapshot["active"],
            "kill_switch": snapshot["kill_switch"],
            "auto_kill": snapshot["auto_kill"],
            "stealth_mode": snapshot["stealth_mode"],
            "stealth_tier": snapshot["stealth_tier"],
            "leak_prediction_score": snapshot["leak_prediction_score"],
        }
        self.shadow_summary.setPlainText(json.dumps(shadow_summary, indent=2))

        persona = self.persona_engine.get_persona("GUI")
        persona_summary = {
            "id": persona.id,
            "fingerprint": persona.device_fingerprint,
            "activity": persona.activity_profile,
            "sync_state": persona.sync_state,
            "risk": persona.risk_level,
            "region": persona.metadata.get("region"),
            "role": persona.metadata.get("role"),
            "stage": persona.metadata.get("evolution_stage"),
            "recent_memory": [
                {"event_type": m.event_type, "details": m.details}
                for m in persona.memory[-5:]
            ],
        }
        self.persona_summary.setPlainText(json.dumps(persona_summary, indent=2))

        lock_state = "ACTIVE" if self.persona_engine.get_lock_state() else "INACTIVE"
        self.persona_lock_label.setText(f"Persona Lock: {lock_state}")

        swarm_state = "ACTIVE" if self.persona_engine.get_swarm_state() else "INACTIVE"
        self.swarm_label.setText(f"Persona Swarm: {swarm_state}")
        self.swarm_summary.setPlainText(json.dumps(self.persona_engine.get_swarm_summary(), indent=2))

        flood_state = "ACTIVE" if self.telemetry_engine.flooder_enabled else "INACTIVE"
        self.flooder_label.setText(f"Identity Flooder v2: {flood_state}")

        logger_mode = "Low-Noise" if logger.low_noise_mode else "Normal"
        self.logger_mode_label.setText(f"Logger Mode: {logger_mode}")

        mode = "Lite (Freeze-Proof)" if self.lite_mode else "Heavy (Verbose)"
        self.lite_mode_label.setText(f"GUI Mode: {mode}")

        self._refresh_log()
        self._refresh_patterns()
        self._refresh_quarantine()
        self._refresh_threat_scores()
        self._refresh_reputation()
        self._refresh_matrix()

    def _refresh_log(self):
        limit = 40 if self.lite_mode else 120
        recent = logger.get_recent(limit=limit)
        self.telemetry_log.setPlainText("\n".join(recent))

    def _refresh_patterns(self):
        snapshot = self.pattern_detector.get_snapshot()
        self.pattern_view.setPlainText(json.dumps(snapshot, indent=2))

    def _refresh_quarantine(self):
        snapshot = self.quarantine.get_snapshot()
        self.quarantine_view.setPlainText(json.dumps(snapshot, indent=2))

    def _refresh_threat_scores(self):
        snapshot = self.threat_scores.get_snapshot()
        self.threat_view.setPlainText(json.dumps(snapshot, indent=2))

    def _refresh_reputation(self):
        snapshot = self.reputation_engine.get_snapshot()
        self.reputation_view.setPlainText(json.dumps(snapshot, indent=2))

    def _refresh_matrix(self):
        snapshot = self.threat_matrix.get_snapshot()
        self.matrix_view.setPlainText(json.dumps(snapshot, indent=2))


# ============================================================
# Main
# ============================================================

logger = SafeLogger()


def main():
    state_store = JsonStateStoreV3("codex_state_v11.json", logger)
    boot_info = compute_boot_info(state_store, logger)

    event_bus = EventBus(logger)
    event_bus.start()

    forge = PersonaForgeV4()
    persona_engine = PersonaEngineV4(state_store, logger, forge)
    identity_shadow = IdentityShadowLayerV4(state_store, logger)

    persona_engine.apply_boot_policies(boot_info)
    identity_shadow.apply_boot_policies(boot_info)

    pattern_detector = PatternDetectorV3(state_store, logger)
    quarantine = SubsystemQuarantine(state_store, logger)
    mirage = TelemetryMirageV4(logger)
    honeypot = HoneypotSandbox(logger)
    threat_scores = ThreatScoreStore(state_store, logger)
    reputation_engine = ReputationEngine(state_store, logger)
    mesh_cluster = MeshClusterV2(state_store, logger)
    threat_matrix = ThreatMatrixV2(state_store, logger)
    gpu_inference = GPUInferenceV2(logger)
    suricata = SuricataEngineV7(state_store, logger)

    telemetry_engine = FakeTelemetryEngineV4(
        persona_engine,
        identity_shadow,
        logger,
        pattern_detector,
        quarantine,
        mirage,
        honeypot,
        event_bus,
    )

    agentic_core = AgenticCoreV1(
        logger,
        event_bus,
        pattern_detector,
        threat_scores,
        reputation_engine,
        identity_shadow,
        persona_engine,
        quarantine,
        mesh_cluster,
        threat_matrix,
        gpu_inference,
        suricata,
        telemetry_engine,
    )

    self_healing = SelfHealingEngineV2(
        logger,
        state_store,
        identity_shadow,
        persona_engine,
        pattern_detector,
        quarantine,
        threat_scores,
        reputation_engine,
        mesh_cluster,
    )

    ndis_engine = NDISPacketEngine(logger, event_bus)

    telemetry_engine.start()
    ndis_engine.start()

    if QtWidgets is None:
        logger.log("PyQt5 not available; running headless autonomous mode.")
        for name in ["EdgeSync", "MicrosoftStore", "Telemetry", "CloudSync", "VPN"]:
            telemetry_engine.submit_identity_access(name)
            time.sleep(1.0)
        time.sleep(10.0)
        telemetry_engine.stop()
        ndis_engine.stop()
        self_healing.stop()
        event_bus.stop()
        return

    app = QtWidgets.QApplication([])
    gui = CodexQtGUI(
        logger,
        identity_shadow,
        persona_engine,
        telemetry_engine,
        pattern_detector,
        quarantine,
        threat_scores,
        reputation_engine,
        threat_matrix,
    )

    def on_close():
        telemetry_engine.stop()
        ndis_engine.stop()
        self_healing.stop()
        event_bus.stop()
        gui.close()

    gui.closeEvent = lambda event: (on_close(), event.accept())
    gui.show()
    app.exec_()


if __name__ == "__main__":
    main()
