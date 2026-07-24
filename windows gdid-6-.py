#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Purge Shell – Unified Python File v6
Fake Telemetry + Persona Engine + IdentityCRL Shadow Layer

Upgrades (v6):
- Multi-tier Stealth (Stealth-L1/L2/L3) with identity-null decay
- Aggressive Auto-Kill bias (fast escalation on leak patterns)
- Expanded Persona Forge (apps, habits, device archetypes, network style)
- Autonomous Swarm Manager (size tuning, rotation cadence, entropy injection)
- Threat Scoring Engine (per-subsystem risk score)
- Deep Pattern Detector (time windows, burst detection, spike classification)
- Enhanced Telemetry Mirage (session timelines, stacked events)
- Strict Quarantine (hard fake-only identity, extended watch)
- Adaptive Logging Mode (normal vs low-noise stealth logging)
- Scheduled Persona Rotation (time-based + event-based)
- Identity Flooder v2 (burst waves, randomized persona mixes)
- Stealth Tier Auto-Adjust (based on threat score + leak history)
- Boot Continuity v2 (persona lineage, resurrection with history tags)

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
        self.low_noise_mode: bool = False

    def log(self, msg: str, force: bool = False):
        if self.low_noise_mode and not force:
            return
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"[{ts}] {msg}"
        with self._lock:
            self._entries.append(line)
        print(line)

    def get_recent(self, limit: int = 200) -> List[str]:
        with self._lock:
            return self._entries[-limit:]

    def set_low_noise(self, enabled: bool):
        self.low_noise_mode = enabled
        self.log(f"[Logger] Low-noise mode set to {enabled}", force=True)


class JsonStateStore:
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

    if first_boot:
        logger.log("[IntegrityCheck] First boot detected. Validating state structure.")
        for key in ["persona", "identity_shadow", "ml_patterns", "quarantine", "threat_scores"]:
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
# Persona Forge v2 (More Realistic Synthetic Personas)
# ============================================================

class PersonaForge:
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

    def forge_persona(self) -> Dict[str, Any]:
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
        }
        return {
            "id": pid,
            "device_fingerprint": fingerprint,
            "activity_profile": activity,
            "sync_state": sync_state,
            "risk_level": risk,
            "metadata": metadata,
        }


# ============================================================
# Persona Engine v2 (Swarm Manager + Scheduled Rotation + Lineage)
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
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger, forge: PersonaForge):
        self.state_store = state_store
        self.logger = logger
        self.forge = forge
        self._lock = threading.Lock()

        self.current_persona: Optional[FakePersona] = None
        self.persona_locked: bool = False

        self.swarm_enabled: bool = False
        self.swarm_personas: List[FakePersona] = []
        self.swarm_index: int = 0
        self.swarm_target_size: int = 6

        self.last_rotation_ts: float = time.time()
        self.rotation_interval_sec: float = 900  # 15 minutes

        self._load_or_create_persona()
        self._load_lock_state()
        self._load_swarm_state()

        self._rotation_thread = threading.Thread(target=self._rotation_loop, daemon=True)
        self._rotation_thread.start()

    def _load_or_create_persona(self):
        data = self.state_store.get("persona", None)
        if data:
            self.current_persona = FakePersona(**data)
            self.logger.log("Loaded existing fake persona from state.")
        else:
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.logger.log("Generated new fake persona via Persona Forge v2.")

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
        forged = self.forge.forge_persona()
        return FakePersona(**forged)

    def rotate_persona(self, reason: str = "manual"):
        with self._lock:
            if self.persona_locked:
                self.logger.log(f"Persona rotation requested ({reason}) but Persona Lock is ACTIVE. Rotation skipped.")
                return
            self.current_persona = self._generate_new_persona()
            self._persist_persona()
            self.last_rotation_ts = time.time()
            self.logger.log(f"Persona rotated via Persona Forge v2 (reason={reason}).")

    def _rotation_loop(self):
        while True:
            time.sleep(5)
            with self._lock:
                if self.persona_locked:
                    continue
                if time.time() - self.last_rotation_ts >= self.rotation_interval_sec:
                    self.rotate_persona(reason="scheduled")

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
            if self.swarm_enabled and len(self.swarm_personas) < self.swarm_target_size:
                needed = self.swarm_target_size - len(self.swarm_personas)
                for _ in range(needed):
                    self.swarm_personas.append(self._generate_new_persona())
                self.logger.log(
                    f"Persona Swarm initialized/expanded to {len(self.swarm_personas)} forged personas."
                )
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
        with self._lock:
            if boot_info.first_boot:
                self.logger.log("[BootPolicy] First boot: Persona kept as-is (lineage established).")
            else:
                if self.swarm_enabled and self.swarm_personas:
                    resurrect_index = random.randint(0, len(self.swarm_personas) - 1)
                    resurrected = self.swarm_personas[resurrect_index]
                    self.logger.log(
                        f"[BootPolicy] Cold-Boot Persona Resurrection v2: resurrecting [{resurrected.id}] "
                        f"with lineage [{resurrected.metadata.get('lineage_tag','?')}]."
                    )
                    self.current_persona = resurrected
                    self._persist_persona()
                else:
                    if not self.persona_locked:
                        self.logger.log("[BootPolicy] Reboot detected: rotating persona safely via forge v2.")
                        self.current_persona = self._generate_new_persona()
                        self._persist_persona()
                    else:
                        self.logger.log("[BootPolicy] Reboot detected but Persona Lock ACTIVE; rotation skipped.")


# ============================================================
# IdentityCRL Shadow Layer v2 (Stealth Tiers + Aggressive Auto-Kill)
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
    stealth_tier: int = 0  # 0=off, 1=L1, 2=L2, 3=L3
    reboot_lockdown_until: float = 0.0
    identity_null_decay_ts: float = 0.0


class IdentityShadowLayer:
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
        self.state.auto_kill = True  # aggressive bias
        self.state.stealth_mode = False
        self.state.stealth_tier = 0
        self.state.reboot_lockdown_until = 0.0
        self.state.last_rotation_ts = time.time()
        self.state.identity_null_decay_ts = 0.0
        self.logger.log(
            f"Initialized Identity Shadow v2: real_hex={self.state.real_lid_hex}, "
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
            if self.state.stealth_mode and self.state.stealth_tier == 0:
                self.state.stealth_tier = 1
            if not self.state.stealth_mode:
                self.state.stealth_tier = 0
            state = "ACTIVE" if self.state.stealth_mode else "INACTIVE"
            self.logger.log(f"Stealth Mode toggled: {state} (tier={self.state.stealth_tier})")
            self._persist_state()

    def set_stealth_tier(self, tier: int):
        with self._lock:
            tier = max(0, min(3, tier))
            self.state.stealth_tier = tier
            self.state.stealth_mode = tier > 0
            self.logger.log(f"Stealth tier set to {tier} (mode={self.state.stealth_mode})")
            self._persist_state()

    def rotate_fake_lid(self):
        with self._lock:
            self.state.fake_lid_numeric = self._generate_fake_lid()
            self.state.last_rotation_ts = time.time()
            self.logger.log("Fake LID rotated.")
            self._persist_state()

    def apply_boot_policies(self, boot_info: BootInfo):
        with self._lock:
            if boot_info.first_boot:
                self.state.stealth_mode = True
                self.state.stealth_tier = 1
                self.logger.log("[BootPolicy] First boot: Stealth Mode AUTO-ENABLED (tier=1).")
            else:
                lockdown_duration = 300
                self.state.reboot_lockdown_until = boot_info.current_boot_ts + lockdown_duration
                self.logger.log(
                    f"[BootPolicy] Reboot detected: Lockdown timer set for {lockdown_duration}s."
                )
            self._persist_state()

    def _lockdown_active(self) -> bool:
        return time.time() < self.state.reboot_lockdown_until

    def _identity_null_active(self) -> bool:
        return self.state.stealth_mode and self.state.stealth_tier >= 2

    def get_effective_lid(self, subsystem: str) -> int:
        with self._lock:
            if self._identity_null_active():
                self.logger.log(
                    f"[Stealth-L{self.state.stealth_tier}] Subsystem {subsystem} requested identity. Identity-null returned."
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
                    f"[AutoKill] Leak detected for subsystem [{subsystem}]. Kill Switch ACTIVATED (aggressive)."
                )
                self._persist_state()
                return self.state.fake_lid_numeric or self._generate_fake_lid()

            return self.state.real_lid_numeric or 0

    def _log_leak(self, subsystem: str):
        self.logger.log(
            f"[LeakDetector] Potential real LID usage by subsystem [{subsystem}] "
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
            }


# ============================================================
# Deep Pattern Detector + Threat Scoring
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


class PatternDetector:
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
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
            self.logger.log(f"[ML] Loaded pattern detector state for {len(self.subsystems)} subsystems.")
        except Exception as e:
            self.logger.log(f"[ML] Error loading pattern state: {e}")
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
            score = 0.0
            score += stats.access_count * 0.5
            score += stats.leak_count * 5.0
            score += stats.flood_count * 0.2
            score += stats.burst_count * 1.0
            if "Sync" in subsystem or "Cloud" in subsystem:
                score += 10.0
            return score

    def is_suspicious(self, subsystem: str) -> bool:
        return self.compute_threat_score(subsystem) >= 25.0

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                name: {
                    "access_count": stats.access_count,
                    "last_access_ts": stats.last_access_ts,
                    "leak_count": stats.leak_count,
                    "flood_count": stats.flood_count,
                    "burst_count": stats.burst_count,
                    "last_burst_ts": stats.last_burst_ts,
                    "threat_score": self.compute_threat_score(name),
                }
                for name, stats in self.subsystems.items()
            }


class ThreatScoreStore:
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
        self.state_store = state_store
        self.logger = logger
        self._lock = threading.Lock()
        self.scores: Dict[str, float] = {}
        self._load()

    def _load(self):
        data = self.state_store.get("threat_scores", {})
        self.scores = {k: float(v) for k, v in data.items()}

    def _persist(self):
        self.state_store.set("threat_scores", self.scores)

    def set_score(self, subsystem: str, score: float):
        with self._lock:
            self.scores[subsystem] = score
            self._persist()

    def get_snapshot(self) -> Dict[str, float]:
        with self._lock:
            return dict(self.scores)


# ============================================================
# Subsystem Quarantine v2
# ============================================================

class SubsystemQuarantine:
    def __init__(self, state_store: JsonStateStore, logger: SafeLogger):
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
            self.logger.log(f"[Quarantine] Subsystem [{subsystem}] quarantined (strict fake-only identity).")
            self._persist_state()

    def is_quarantined(self, subsystem: str) -> bool:
        with self._lock:
            return subsystem in self.quarantined

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.quarantined)


# ============================================================
# Telemetry Mirage v2 (Session Timelines)
# ============================================================

class TelemetryMirage:
    def __init__(self, logger: SafeLogger):
        self.logger = logger

    def generate_mirage_session(self, subsystem: str, persona: FakePersona):
        events = []
        base_ts = time.time()
        for i in range(4):
            event_type = random.choice(
                ["browsing", "app_usage", "sync", "health", "error"]
            )
            payload = {
                "subsystem": subsystem,
                "persona_id": persona.id,
                "fingerprint": persona.device_fingerprint,
                "region": persona.metadata.get("region", "Unknown"),
                "event_type": event_type,
                "ts": base_ts + i * random.uniform(1.0, 5.0),
                "apps": persona.metadata.get("apps", []),
                "network_style": persona.metadata.get("network_style", "Unknown"),
            }
            events.append(payload)
            self.logger.log(
                f"[Mirage] Synthetic {event_type} session event for [{subsystem}] persona [{persona.id}]."
            )
        return events


# ============================================================
# Threat-Adaptive Controller v2
# ============================================================

class ThreatAdaptiveController:
    def __init__(
        self,
        logger: SafeLogger,
        identity_shadow: IdentityShadowLayer,
        persona_engine: PersonaEngine,
        telemetry_engine: "FakeTelemetryEngine",
        pattern_detector: PatternDetector,
        quarantine: SubsystemQuarantine,
        threat_scores: ThreatScoreStore,
    ):
        self.logger = logger
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.telemetry_engine = telemetry_engine
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.threat_scores = threat_scores
        self._lock = threading.Lock()

        self.telemetry_counter: int = 0
        self.identity_access_counter: int = 0

    def record_identity_access(self, subsystem: str):
        with self._lock:
            self.identity_access_counter += 1
        self.pattern_detector.record_access(subsystem)
        self._evaluate(subsystem)

    def record_leak(self, subsystem: str):
        self.pattern_detector.record_leak(subsystem)
        self._evaluate(subsystem)

    def record_telemetry(self, subsystem: str):
        with self._lock:
            self.telemetry_counter += 1
        self._evaluate(subsystem)

    def _evaluate(self, subsystem: str):
        score = self.pattern_detector.compute_threat_score(subsystem)
        self.threat_scores.set_score(subsystem, score)

        if self.pattern_detector.is_suspicious(subsystem):
            if not self.quarantine.is_quarantined(subsystem):
                self.quarantine.quarantine(subsystem)

        if self.telemetry_counter >= 50:
            self.logger.log("[ThreatAdaptive] Telemetry spike detected -> auto-stealth tier 2.")
            self.identity_shadow.set_stealth_tier(2)
            self.telemetry_counter = 0

        if score >= 40.0:
            if not self.persona_engine.get_swarm_state():
                self.logger.log("[ThreatAdaptive] High threat score -> auto-swarm.")
                self.persona_engine.toggle_swarm()

        if "Sync" in subsystem or "Cloud" in subsystem:
            self.logger.log("[ThreatAdaptive] Sync-like subsystem detected -> auto-kill.")
            self.identity_shadow.toggle_kill_switch()

        if score >= 60.0:
            self.logger.log("[ThreatAdaptive] Very high threat score -> Stealth tier 3 + Flooder.")
            self.identity_shadow.set_stealth_tier(3)
            if not self.telemetry_engine.flooder_enabled:
                self.telemetry_engine.toggle_flooder()


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
        self.logger.log(f"Honeypot recorded event: {event.get('type', 'unknown')}")

    def get_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return self._events[-limit:]


# ============================================================
# Fake Telemetry Engine v2 (Flooder v2 + Glyphs + Mirage v2)
# ============================================================

class FakeTelemetryEngine:
    def __init__(
        self,
        persona_engine: PersonaEngine,
        identity_shadow: IdentityShadowLayer,
        logger: SafeLogger,
        pattern_detector: PatternDetector,
        quarantine: SubsystemQuarantine,
        mirage: TelemetryMirage,
        honeypot: HoneypotSandbox,
    ):
        self.persona_engine = persona_engine
        self.identity_shadow = identity_shadow
        self.logger = logger
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.mirage = mirage
        self.honeypot = honeypot
        self._lock = threading.Lock()
        self._event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.flooder_enabled: bool = False
        self.threat_controller: Optional[ThreatAdaptiveController] = None

    def attach_threat_controller(self, controller: ThreatAdaptiveController):
        self.threat_controller = controller

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True)
                self._thread.start()
                self.logger.log("Fake Telemetry Engine v2 started.")

    def stop(self):
        with self._lock:
            self._running = False
        self.logger.log("Fake Telemetry Engine v2 stopped.")

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

        if self.threat_controller:
            self.threat_controller.record_identity_access(subsystem)

        self.pattern_detector.record_access(subsystem)

        event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona": persona.__dict__,
            "effective_lid": effective_lid,
            "shadow_active": snapshot["active"],
            "kill_switch": snapshot["kill_switch"],
            "auto_kill": snapshot["auto_kill"],
            "stealth_mode": snapshot["stealth_mode"],
            "stealth_tier": snapshot["stealth_tier"],
            "lockdown_until": snapshot["reboot_lockdown_until"],
            "ts": time.time(),
        }
        self._event_queue.put(event)

    def toggle_flooder(self):
        with self._lock:
            self.flooder_enabled = not self.flooder_enabled
            state = "ACTIVE" if self.flooder_enabled else "INACTIVE"
            self.logger.log(f"Identity Flooder v2 toggled: {state}")

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
        stealth_tier = event["stealth_tier"]
        subsystem = event["subsystem"]

        glyph = self._glyph_for_state(shadow_active, kill_switch, stealth_mode, stealth_tier)
        mode_tags = []
        if kill_switch:
            mode_tags.append("KillSwitch")
        if shadow_active:
            mode_tags.append("Shadow")
        if auto_kill:
            mode_tags.append("AutoKill")
        if stealth_mode:
            mode_tags.append(f"Stealth-L{stealth_tier}")
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

        self.mirage.generate_mirage_session(subsystem, persona)

        honeypot_event = {
            "type": "identity_access",
            "subsystem": subsystem,
            "persona_id": persona.id,
            "ts": time.time(),
        }
        self.honeypot.record_event(honeypot_event)

        if self.flooder_enabled:
            self._identity_flood(subsystem)

    def _glyph_for_state(self, shadow_active: bool, kill_switch: bool, stealth_mode: bool, stealth_tier: int) -> str:
        if stealth_mode:
            if stealth_tier == 3:
                return "▣"
            if stealth_tier == 2:
                return "□"
            return "◻"
        if kill_switch:
            return "■"
        if shadow_active:
            return "●"
        return "▲"

    def _identity_flood(self, subsystem: str):
        burst_size = random.randint(3, 6)
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
            if self.threat_controller:
                self.threat_controller.record_telemetry(subsystem)


# ============================================================
# GUI v2
# ============================================================

class CodexGUI:
    def __init__(
        self,
        root: tk.Tk,
        logger: SafeLogger,
        identity_shadow: IdentityShadowLayer,
        persona_engine: PersonaEngine,
        telemetry_engine: FakeTelemetryEngine,
        pattern_detector: PatternDetector,
        quarantine: SubsystemQuarantine,
        threat_scores: ThreatScoreStore,
    ):
        self.root = root
        self.logger = logger
        self.identity_shadow = identity_shadow
        self.persona_engine = persona_engine
        self.telemetry_engine = telemetry_engine
        self.pattern_detector = pattern_detector
        self.quarantine = quarantine
        self.threat_scores = threat_scores

        self.root.title("Codex Purge Shell – Identity Shadow Layer v6")
        self.root.geometry("1250x780")

        self._build_layout()
        self._refresh_ui()
        self._schedule_refresh()

    def _build_layout(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Identity Shadow Panel
        self.shadow_frame = ttk.LabelFrame(self.main_frame, text="Identity Shadow Layer v6")
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

        self.stealth_tier_label = ttk.Label(self.shadow_frame, text="Stealth Tier: Unknown")
        self.stealth_tier_label.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        self.stealth_tier_btn1 = ttk.Button(
            self.shadow_frame, text="Tier 1", command=lambda: self._set_stealth_tier(1)
        )
        self.stealth_tier_btn1.grid(row=4, column=1, sticky="e", padx=5, pady=5)

        self.stealth_tier_btn2 = ttk.Button(
            self.shadow_frame, text="Tier 2", command=lambda: self._set_stealth_tier(2)
        )
        self.stealth_tier_btn2.grid(row=4, column=2, sticky="e", padx=5, pady=5)

        self.stealth_tier_btn3 = ttk.Button(
            self.shadow_frame, text="Tier 3", command=lambda: self._set_stealth_tier(3)
        )
        self.stealth_tier_btn3.grid(row=4, column=3, sticky="e", padx=5, pady=5)

        self.rotate_lid_btn = ttk.Button(
            self.shadow_frame, text="Rotate Fake LID Now", command=self._rotate_fake_lid
        )
        self.rotate_lid_btn.grid(row=0, column=2, sticky="e", padx=5, pady=5)

        self.shadow_info_text = tk.Text(self.shadow_frame, height=7, width=150)
        self.shadow_info_text.grid(row=5, column=0, columnspan=4, padx=5, pady=5)

        # Persona Panel
        self.persona_frame = ttk.LabelFrame(self.main_frame, text="Fake Persona Metadata v2")
        self.persona_frame.pack(fill=tk.X, padx=5, pady=5)

        self.persona_info_text = tk.Text(self.persona_frame, height=8, width=150)
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
        self.telemetry_frame = ttk.LabelFrame(self.main_frame, text="Identity Access Log (Glyph-coded v2)")
        self.telemetry_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.telemetry_text = tk.Text(self.telemetry_frame, height=15, width=150)
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

        self.flooder_label = ttk.Label(self.telemetry_frame, text="Identity Flooder v2: Unknown")
        self.flooder_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.flooder_btn = ttk.Button(
            self.telemetry_frame, text="Toggle Flooder v2", command=self._toggle_flooder
        )
        self.flooder_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.logger_mode_label = ttk.Label(self.telemetry_frame, text="Logger Mode: Normal")
        self.logger_mode_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.logger_mode_btn = ttk.Button(
            self.telemetry_frame, text="Toggle Low-Noise", command=self._toggle_logger_mode
        )
        self.logger_mode_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Pattern / Quarantine / Threat Panel
        self.pattern_frame = ttk.LabelFrame(self.main_frame, text="Pattern Detector & Quarantine & Threat Scores")
        self.pattern_frame.pack(fill=tk.X, padx=5, pady=5)

        self.pattern_text = tk.Text(self.pattern_frame, height=6, width=150)
        self.pattern_text.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

        self.quarantine_text = tk.Text(self.pattern_frame, height=4, width=150)
        self.quarantine_text.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.threat_text = tk.Text(self.pattern_frame, height=4, width=150)
        self.threat_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # Glyph Legend
        self.legend_frame = ttk.LabelFrame(self.main_frame, text="Glyph Legend v2")
        self.legend_frame.pack(fill=tk.X, padx=5, pady=5)

        legend_text = (
            "■ Kill Switch / Lockdown ACTIVE – hard block, real identity never leaves.\n"
            "● Shadow ACTIVE – fake identity used, real identity shadowed.\n"
            "▲ Shadow OFF & Kill Switch OFF – potential leak, Leak Detector watching.\n"
            "◻ Stealth-L1 – light stealth, fake identity bias.\n"
            "□ Stealth-L2 – strong stealth, identity-null bias.\n"
            "▣ Stealth-L3 – maximum stealth, identity-null enforced.\n"
            "◆ Flood v2 – Identity Flooder generating burst fake identity noise."
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

    def _simulate_identity_access(self, subsystem: str):
        self.telemetry_engine.submit_identity_access(subsystem)

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
            if stealth_tier == 3:
                glyph = "▣"
            elif stealth_tier == 2:
                glyph = "□"
            else:
                glyph = "◻"

        self.shadow_status_label.config(text=f"Shadow Status: {status} {glyph}")
        try:
            color = "green" if snapshot["active"] else "red"
            if snapshot["kill_switch"] or time.time() < snapshot["reboot_lockdown_until"]:
                color = "purple"
            if snapshot["stealth_mode"]:
                if stealth_tier == 3:
                    color = "darkblue"
                elif stealth_tier == 2:
                    color = "blue"
                else:
                    color = "lightblue"
            self.shadow_status_label.config(foreground=color)
        except Exception:
            pass

        self.kill_switch_label.config(text=f"Kill Switch: {kill_state} ■")
        self.auto_kill_label.config(text=f"Auto-Kill: {auto_kill_state}")
        self.stealth_label.config(text=f"Stealth Mode: {stealth_state}")
        self.stealth_tier_label.config(text=f"Stealth Tier: {stealth_tier}")

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
        self.flooder_label.config(text=f"Identity Flooder v2: {flood_state}")

        logger_mode = "Low-Noise" if logger.low_noise_mode else "Normal"
        self.logger_mode_label.config(text=f"Logger Mode: {logger_mode}")

        self._refresh_log()
        self._refresh_patterns()
        self._refresh_quarantine()
        self._refresh_threat_scores()

    def _refresh_log(self):
        recent = logger.get_recent(limit=120)
        self.telemetry_text.delete("1.0", tk.END)
        for line in recent:
            self.telemetry_text.insert(tk.END, line + "\n")

    def _refresh_patterns(self):
        snapshot = self.pattern_detector.get_snapshot()
        self.pattern_text.delete("1.0", tk.END)
        self.pattern_text.insert(tk.END, json.dumps(snapshot, indent=2))

    def _refresh_quarantine(self):
        snapshot = self.quarantine.get_snapshot()
        self.quarantine_text.delete("1.0", tk.END)
        self.quarantine_text.insert(tk.END, json.dumps(snapshot, indent=2))

    def _refresh_threat_scores(self):
        snapshot = self.threat_scores.get_snapshot()
        self.threat_text.delete("1.0", tk.END)
        self.threat_text.insert(tk.END, json.dumps(snapshot, indent=2))

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

    forge = PersonaForge()
    persona_engine = PersonaEngine(state_store, logger, forge)
    identity_shadow = IdentityShadowLayer(state_store, logger)

    persona_engine.apply_boot_policies(boot_info)
    identity_shadow.apply_boot_policies(boot_info)

    pattern_detector = PatternDetector(state_store, logger)
    quarantine = SubsystemQuarantine(state_store, logger)
    mirage = TelemetryMirage(logger)
    honeypot = HoneypotSandbox(logger)
    threat_scores = ThreatScoreStore(state_store, logger)

    telemetry_engine = FakeTelemetryEngine(
        persona_engine, identity_shadow, logger, pattern_detector, quarantine, mirage, honeypot
    )

    threat_controller = ThreatAdaptiveController(
        logger, identity_shadow, persona_engine, telemetry_engine, pattern_detector, quarantine, threat_scores
    )
    telemetry_engine.attach_threat_controller(threat_controller)

    telemetry_engine.start()

    if tk is None or ttk is None:
        logger.log("Tkinter not available; running headless.")
        for name in ["EdgeSync", "MicrosoftStore", "Telemetry", "CloudSync"]:
            telemetry_engine.submit_identity_access(name)
            time.sleep(1.0)
        telemetry_engine.stop()
        return

    root = tk.Tk()
    gui = CodexGUI(
        root,
        logger,
        identity_shadow,
        persona_engine,
        telemetry_engine,
        pattern_detector,
        quarantine,
        threat_scores,
    )
    root.protocol("WM_DELETE_WINDOW", lambda: (telemetry_engine.stop(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
