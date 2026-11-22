"""
Live CVE Fetcher + Flaw Checker — Live Test Bench Edition
Python 3.9+ | Standard library only

Notes:
- NVD records describe vulnerabilities; validate applicability against actual
  packages, versions, and configurations on your test bench.
- Guard rules (BLOCK / SANITIZE / AUDIT) apply to functions wrapped with
  GuardRegistry.protect().
- Counterfactual simulations, bypass/overlap diagnostics, hash-chained snapshots,
  learning weights, batch outcomes, and reasoning traces are local deterministic
  engineering tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Lock, Thread
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import copy
import math
import tempfile
import hashlib
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "Live CVE Fetcher + Flaw Checker — Test Bench"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path(__file__).resolve().parent / "cve_cache"
DEFAULT_SANDBOX_DIR = Path(__file__).resolve().parent / "test_bench_sandbox"
DEFAULT_WEIGHTS_PATH = Path(__file__).resolve().parent / "bench_weights.json"
DEFAULT_LEDGER_PATH = Path(__file__).resolve().parent / "bench_ledger.json"

PATH_TRAVERSAL_PATTERN = r"(?:^|[/\\])\.\.(?:[/\\]|$)|^[/\\]"
COMMAND_CHAINING_PATTERN = r"[;&|`$]|\$\("


def parse_cve_queue(raw_text: str) -> list[str]:
    """Parse a comma-separated list of CVE IDs, preserving order and deduplicating."""
    seen: set[str] = set()
    ordered: list[str] = []
    for part in raw_text.split(","):
        cleaned = part.strip().upper()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


class GuardAction(str, Enum):
    BLOCK = "block"
    SANITIZE = "sanitize"
    AUDIT = "audit"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardBlockedError(PermissionError):
    def __init__(self, message: str, event: "GuardEvent") -> None:
        super().__init__(message)
        self.event = event


class PathEscapeError(ValueError):
    pass


@dataclass(frozen=True)
class FlawRecord:
    flaw_id: str
    title: str
    severity: Severity
    probe_name: str
    block_pattern: str
    description: str
    source_url: Optional[str] = None


@dataclass(frozen=True)
class FlawMatch:
    target_name: str
    flaw: FlawRecord
    evidence: str


@dataclass(frozen=True)
class CveBatchOutcome:
    run_id: str
    timestamp: str
    cve_id: str
    status: str
    severity: str
    probe_name: str
    action_taken: str
    matches_count: int
    summary: str


@dataclass(frozen=True)
class GuardEvent:
    timestamp: str
    target_name: str
    guard_name: str
    flaw_id: Optional[str]
    action: GuardAction
    blocked: bool
    reason: str
    args_preview: str


@dataclass
class GuardRule:
    name: str
    target_name: str
    predicate: Callable[..., bool]
    action: GuardAction = GuardAction.BLOCK
    flaw_id: Optional[str] = None
    reason: str = "Matched known flaw pattern"
    enabled: bool = True
    priority: float = 1.0
    block_pattern: str = ""
    sanitizer: Optional[Callable[[str], str]] = None
    hits: int = field(default=0, init=False)


@dataclass(frozen=True)
class ReasoningStep:
    stage: str
    detail: str
    weight_delta: Optional[float] = None


@dataclass
class ReasoningTrace:
    run_id: str
    timestamp: str
    cve_id: str
    mode: str
    steps: list[ReasoningStep] = field(default_factory=list)
    final_decision: str = ""

    def add(self, stage: str, detail: str, weight_delta: Optional[float] = None) -> None:
        self.steps.append(
            ReasoningStep(stage=stage, detail=detail, weight_delta=weight_delta)
        )

    def format_text(self) -> str:
        lines = [
            f"=== Trace {self.run_id} | {self.cve_id} | mode={self.mode} | {self.timestamp} ==="
        ]
        for idx, step in enumerate(self.steps, start=1):
            delta_str = (
                f" [weight_delta={step.weight_delta:+.3f}]"
                if step.weight_delta is not None
                else ""
            )
            lines.append(f"  {idx}. [{step.stage}]{delta_str} {step.detail}")
        if self.final_decision:
            lines.append(f"  -> Outcome: {self.final_decision}")
        return "\n".join(lines)


@dataclass(frozen=True)
class LedgerCheckpoint:
    index: int
    checkpoint_id: str
    timestamp: str
    label: str
    prev_hash: str
    entry_hash: str
    weights_snapshot: dict[str, dict[str, Any]]
    rule_specs: list[dict[str, Any]]


class LearningWeightStore:
    """
    Persists adaptive weights per (flaw_id, target_name, probe_name) key.
    Weights stay bounded in [0.25, 3.00] with neutral baseline 1.00.
    """

    MIN_WEIGHT = 0.25
    MAX_WEIGHT = 3.00
    DEFAULT_WEIGHT = 1.00

    def __init__(self, storage_path: Path = DEFAULT_WEIGHTS_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._weights: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def make_key(flaw_id: str, target_name: str, probe_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}::{probe_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            self._weights = {}
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._weights = data
        except (OSError, json.JSONDecodeError):
            self._weights = {}

    def _save(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.storage_path, self._weights)
        except OSError:
            pass

    def get_weight(self, flaw_id: str, target_name: str, probe_name: str) -> float:
        key = self.make_key(flaw_id, target_name, probe_name)
        with self._lock:
            entry = self._weights.get(key)
            if not isinstance(entry, dict):
                return self.DEFAULT_WEIGHT
            val = entry.get("weight", self.DEFAULT_WEIGHT)
            try:
                return max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, float(val)))
            except (TypeError, ValueError):
                return self.DEFAULT_WEIGHT

    def update_weight(
        self,
        flaw_id: str,
        target_name: str,
        probe_name: str,
        delta: float,
        reason: str,
    ) -> tuple[float, float]:
        key = self.make_key(flaw_id, target_name, probe_name)
        with self._lock:
            current = self.DEFAULT_WEIGHT
            samples = 0
            existing = self._weights.get(key)
            if isinstance(existing, dict):
                try:
                    current = max(
                        self.MIN_WEIGHT,
                        min(self.MAX_WEIGHT, float(existing.get("weight", 1.0))),
                    )
                except (TypeError, ValueError):
                    current = self.DEFAULT_WEIGHT
                samples = int(existing.get("samples", 0) or 0)

            updated = max(
                self.MIN_WEIGHT, min(self.MAX_WEIGHT, round(current + delta, 4))
            )
            actual_delta = round(updated - current, 4)
            self._weights[key] = {
                "flaw_id": flaw_id.upper(),
                "target_name": target_name,
                "probe_name": probe_name,
                "weight": updated,
                "samples": samples + 1,
                "last_reason": reason,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save()
            return updated, actual_delta

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._weights)

    def restore_snapshot(self, snap: dict[str, dict[str, Any]]) -> None:
        with self._lock:
            self._weights = copy.deepcopy(snap)
            self._save()

    def reset(self) -> None:
        with self._lock:
            self._weights.clear()
            self._save()


class RemediationEngine:
    """
    Produces context-aware string fixes for matched flaw patterns and verifies
    guarded targets post-remediation.
    """

    @staticmethod
    def build_sanitizer(flaw: FlawRecord) -> Callable[[str], str]:
        pattern = flaw.block_pattern
        probe = flaw.probe_name

        def _sanitize(raw: str) -> str:
            if not isinstance(raw, str):
                return raw
            text = raw
            if (
                probe == "check_path_resolution"
                or "traversal" in flaw.description.lower()
            ):
                normalized = posixpath.normpath(text.replace("\\", "/"))
                parts = [
                    p for p in normalized.split("/") if p and p not in (".", "..")
                ]
                text = "/".join(parts)
            if (
                probe == "check_command_tokenization"
                or "command" in flaw.description.lower()
            ):
                text = re.sub(r"[;&|`$]|\$\([^)]*\)", " ", text)
                text = re.sub(r"\s+", " ", text).strip()
            if pattern and text == raw:
                try:
                    text = re.sub(pattern, "", text, flags=re.IGNORECASE).strip()
                except re.error:
                    pass
            return text

        return _sanitize


class GuardRegistry:
    """In-process runtime guards for functions wrapped with @registry.protect."""

    def __init__(self, weights: Optional[LearningWeightStore] = None) -> None:
        self._rules: dict[str, list[GuardRule]] = {}
        self._events: list[GuardEvent] = []
        self.weights = weights

    def register(self, rule: GuardRule) -> None:
        rules = self._rules.setdefault(rule.target_name, [])
        for index, old in enumerate(rules):
            if old.name == rule.name:
                rules[index] = rule
                rules.sort(key=lambda r: r.priority, reverse=True)
                return
        rules.append(rule)
        rules.sort(key=lambda r: r.priority, reverse=True)

    def rules_for(self, target_name: str) -> list[GuardRule]:
        return list(self._rules.get(target_name, []))

    def all_rules(self) -> list[GuardRule]:
        out: list[GuardRule] = []
        for rlist in self._rules.values():
            out.extend(rlist)
        return out

    def export_rule_specs(self) -> list[dict[str, Any]]:
        specs: list[dict[str, Any]] = []
        for rule in self.all_rules():
            specs.append(
                {
                    "name": rule.name,
                    "target_name": rule.target_name,
                    "action": rule.action.value,
                    "flaw_id": rule.flaw_id,
                    "reason": rule.reason,
                    "enabled": rule.enabled,
                    "priority": rule.priority,
                    "block_pattern": rule.block_pattern,
                }
            )
        return specs

    def restore_rule_specs(self, specs: list[dict[str, Any]]) -> None:
        self._rules.clear()
        for spec in specs:
            pattern = spec.get("block_pattern") or ""
            try:
                compiled = re.compile(pattern, re.IGNORECASE) if pattern else None
            except re.error:
                compiled = None

            def _make_pred(rx: Optional[re.Pattern[str]]) -> Callable[..., bool]:
                def _pred(*args: Any, **kwargs: Any) -> bool:
                    if rx is None:
                        return False
                    return any(
                        bool(rx.search(s)) for s in _iter_string_inputs(args, kwargs)
                    )

                return _pred

            action_val = spec.get("action", GuardAction.BLOCK.value)
            try:
                action_enum = GuardAction(action_val)
            except ValueError:
                action_enum = GuardAction.BLOCK

            flaw_stub = FlawRecord(
                flaw_id=spec.get("flaw_id") or "UNKNOWN",
                title="",
                severity=Severity.HIGH,
                probe_name=(
                    "check_path_resolution"
                    if "path" in (spec.get("target_name") or "")
                    else "check_command_tokenization"
                ),
                block_pattern=pattern,
                description="",
            )
            sanitizer = (
                RemediationEngine.build_sanitizer(flaw_stub)
                if action_enum == GuardAction.SANITIZE
                else None
            )
            self.register(
                GuardRule(
                    name=spec["name"],
                    target_name=spec["target_name"],
                    predicate=_make_pred(compiled),
                    action=action_enum,
                    flaw_id=spec.get("flaw_id"),
                    reason=spec.get("reason") or "Restored rule",
                    enabled=bool(spec.get("enabled", True)),
                    priority=float(spec.get("priority", 1.0)),
                    block_pattern=pattern,
                    sanitizer=sanitizer,
                )
            )

    def clear_events(self) -> None:
        self._events.clear()

    @property
    def events(self) -> list[GuardEvent]:
        return list(self._events)

    @staticmethod
    def _format_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        try:
            result = ", ".join(
                [repr(x) for x in args] + [f"{k}={v!r}" for k, v in kwargs.items()]
            )
        except Exception:
            result = "<arguments could not be represented>"
        return result if len(result) <= 160 else result[:157] + "..."

    def _record(
        self,
        rule: GuardRule,
        blocked: bool,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> GuardEvent:
        rule.hits += 1
        event = GuardEvent(
            datetime.now(timezone.utc).isoformat(),
            rule.target_name,
            rule.name,
            rule.flaw_id,
            rule.action,
            blocked,
            rule.reason,
            self._format_args(args, kwargs),
        )
        self._events.append(event)
        return event

    def _sanitize_string(self, value: str, rule: GuardRule) -> str:
        if rule.sanitizer is not None:
            return rule.sanitizer(value)
        if rule.block_pattern:
            try:
                return re.sub(rule.block_pattern, "", value, flags=re.IGNORECASE)
            except re.error:
                return value
        return value

    def _sanitize_value(self, value: Any, rule: GuardRule) -> Any:
        if isinstance(value, str):
            return self._sanitize_string(value, rule)
        if isinstance(value, list):
            return [self._sanitize_value(item, rule) for item in value]
        if isinstance(value, tuple):
            return tuple(self._sanitize_value(item, rule) for item in value)
        if isinstance(value, dict):
            return {k: self._sanitize_value(v, rule) for k, v in value.items()}
        return value

    def _apply_sanitize(
        self,
        rule: GuardRule,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        new_args = tuple(self._sanitize_value(arg, rule) for arg in args)
        new_kwargs = {k: self._sanitize_value(v, rule) for k, v in kwargs.items()}
        self._record(rule, blocked=False, args=args, kwargs=kwargs)
        return new_args, new_kwargs

    def protect(self, func: Callable[..., Any]) -> Callable[..., Any]:
        target_name = func.__name__

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            active_args = args
            active_kwargs = dict(kwargs)

            for rule in self._rules.get(target_name, []):
                if not rule.enabled:
                    continue
                try:
                    matched = bool(rule.predicate(*active_args, **active_kwargs))
                except Exception as exc:
                    if rule.action == GuardAction.BLOCK:
                        event = self._record(rule, True, active_args, active_kwargs)
                        raise GuardBlockedError(
                            f"Guard predicate failed; call blocked: {exc}", event
                        ) from exc
                    continue

                if matched:
                    if rule.action == GuardAction.BLOCK:
                        event = self._record(rule, True, active_args, active_kwargs)
                        raise GuardBlockedError(
                            f"[{target_name}] BLOCKED ({rule.flaw_id or rule.name}): "
                            f"{rule.reason}",
                            event,
                        )
                    if rule.action == GuardAction.SANITIZE:
                        active_args, active_kwargs = self._apply_sanitize(
                            rule, active_args, active_kwargs
                        )
                    elif rule.action == GuardAction.AUDIT:
                        self._record(rule, False, active_args, active_kwargs)

            return func(*active_args, **active_kwargs)

        return wrapper


class RollbackLedger:
    """
    Hash-chained snapshot ledger for guard rules and learned weights.
    Supports verifying chain integrity and rolling back to any prior checkpoint.
    """

    def __init__(self, ledger_path: Path = DEFAULT_LEDGER_PATH) -> None:
        self.ledger_path = Path(ledger_path)
        self._lock = Lock()
        self._checkpoints: list[LedgerCheckpoint] = []
        self._load()

    @staticmethod
    def _compute_hash(
        index: int,
        timestamp: str,
        label: str,
        prev_hash: str,
        weights_snapshot: dict[str, dict[str, Any]],
        rule_specs: list[dict[str, Any]],
    ) -> str:
        canonical = json.dumps(
            {
                "index": index,
                "timestamp": timestamp,
                "label": label,
                "prev_hash": prev_hash,
                "weights": weights_snapshot,
                "rules": rule_specs,
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _load(self) -> None:
        if not self.ledger_path.exists():
            self._checkpoints = []
            return
        try:
            raw = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                self._checkpoints = []
                return
            restored: list[LedgerCheckpoint] = []
            for item in raw:
                if isinstance(item, dict) and "entry_hash" in item:
                    restored.append(
                        LedgerCheckpoint(
                            index=int(item["index"]),
                            checkpoint_id=str(item["checkpoint_id"]),
                            timestamp=str(item["timestamp"]),
                            label=str(item["label"]),
                            prev_hash=str(item["prev_hash"]),
                            entry_hash=str(item["entry_hash"]),
                            weights_snapshot=item.get("weights_snapshot") or {},
                            rule_specs=item.get("rule_specs") or [],
                        )
                    )
            self._checkpoints = restored
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            self._checkpoints = []

    def _save(self) -> None:
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            payload = [
                {
                    "index": cp.index,
                    "checkpoint_id": cp.checkpoint_id,
                    "timestamp": cp.timestamp,
                    "label": cp.label,
                    "prev_hash": cp.prev_hash,
                    "entry_hash": cp.entry_hash,
                    "weights_snapshot": cp.weights_snapshot,
                    "rule_specs": cp.rule_specs,
                }
                for cp in self._checkpoints
            ]
            atomic_write_json(self.ledger_path, payload)
        except OSError:
            pass

    def record_checkpoint(
        self,
        label: str,
        weights_snapshot: dict[str, dict[str, Any]],
        rule_specs: list[dict[str, Any]],
    ) -> LedgerCheckpoint:
        with self._lock:
            idx = len(self._checkpoints)
            prev_hash = (
                self._checkpoints[-1].entry_hash if self._checkpoints else "GENESIS"
            )
            ts = datetime.now(timezone.utc).isoformat()
            cp_id = f"CP-{idx + 1:04d}"
            w_copy = copy.deepcopy(weights_snapshot)
            r_copy = copy.deepcopy(rule_specs)
            entry_hash = self._compute_hash(idx, ts, label, prev_hash, w_copy, r_copy)
            cp = LedgerCheckpoint(
                index=idx,
                checkpoint_id=cp_id,
                timestamp=ts,
                label=label,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                weights_snapshot=w_copy,
                rule_specs=r_copy,
            )
            self._checkpoints.append(cp)
            self._save()
            return cp

    def checkpoints(self) -> list[LedgerCheckpoint]:
        with self._lock:
            return list(self._checkpoints)

    def get_by_id(self, checkpoint_id: str) -> Optional[LedgerCheckpoint]:
        with self._lock:
            for cp in self._checkpoints:
                if cp.checkpoint_id.upper() == checkpoint_id.strip().upper():
                    return cp
            return None

    def verify_integrity(self) -> tuple[bool, str]:
        with self._lock:
            if not self._checkpoints:
                return True, "Ledger is empty (valid genesis state)."
            expected_prev = "GENESIS"
            for cp in self._checkpoints:
                if cp.prev_hash != expected_prev:
                    return (
                        False,
                        f"Broken prev_hash link at {cp.checkpoint_id} (index {cp.index}).",
                    )
                recomputed = self._compute_hash(
                    cp.index,
                    cp.timestamp,
                    cp.label,
                    cp.prev_hash,
                    cp.weights_snapshot,
                    cp.rule_specs,
                )
                if recomputed != cp.entry_hash:
                    return (
                        False,
                        f"Hash mismatch at {cp.checkpoint_id} (data tampered or corrupted).",
                    )
                expected_prev = cp.entry_hash
            return (
                True,
                f"Chain verified: {len(self._checkpoints)} checkpoint(s) intact.",
            )


class CounterfactualSimulator:
    """
    Simulates what-if outcomes across representative test inputs for BLOCK,
    SANITIZE, and AUDIT without mutating live registry state.
    """

    SAMPLE_INPUTS: dict[str, list[str]] = {
        "resolve_bench_path": [
            "reports/2026/summary.json",
            "../outside-bench/target.conf",
            "..\\..\\windows\\win.ini",
        ],
        "parse_bench_command_tokens": [
            "status --verbose",
            "status --verbose; echo check_token",
            "status $(whoami) | cat",
        ],
    }

    @classmethod
    def simulate(
        cls,
        flaw: FlawRecord,
        target_name: str,
        sanitizer_fn: Optional[Callable[[str], str]] = None,
    ) -> list[dict[str, str]]:
        samples = cls.SAMPLE_INPUTS.get(
            target_name, ["benign_input", "../escape_probe", "cmd; token"]
        )
        try:
            rx = (
                re.compile(flaw.block_pattern, re.IGNORECASE)
                if flaw.block_pattern
                else None
            )
        except re.error:
            rx = None

        rows: list[dict[str, str]] = []
        for sample in samples:
            matched = bool(rx.search(sample)) if rx else False
            if not matched:
                rows.append(
                    {
                        "input": sample,
                        "matched": "no",
                        "block_outcome": "PASS (unmatched)",
                        "sanitize_outcome": f"PASS -> {sample!r}",
                        "audit_outcome": "PASS (unmatched)",
                    }
                )
                continue

            sanitized = (
                sanitizer_fn(sample)
                if sanitizer_fn is not None
                else (
                    re.sub(flaw.block_pattern, "", sample, flags=re.IGNORECASE).strip()
                    if flaw.block_pattern
                    else sample
                )
            )
            rows.append(
                {
                    "input": sample,
                    "matched": "yes",
                    "block_outcome": "BLOCK (GuardBlockedError)",
                    "sanitize_outcome": f"REWRITE -> {sanitized!r}",
                    "audit_outcome": "PASS + AUDIT EVENT",
                }
            )
        return rows


class RuleDiagnostics:
    """Detects overlapping rules on a target and potential pattern bypass vectors."""

    BYPASS_CANDIDATES: dict[str, list[str]] = {
        "check_path_resolution": [
            "....//....//etc/passwd",
            "..%2f..%2fetc/passwd",
            "subdir/./valid.txt",
        ],
        "check_command_tokenization": [
            "status\nrm -rf /tmp/x",
            "status &background_job",
            "status `id`",
        ],
    }

    @staticmethod
    def analyze_target(target_name: str, rules: list[GuardRule]) -> list[str]:
        findings: list[str] = []
        enabled_rules = [r for r in rules if r.enabled]
        if len(enabled_rules) > 1:
            for i in range(len(enabled_rules)):
                for j in range(i + 1, len(enabled_rules)):
                    a, b = enabled_rules[i], enabled_rules[j]
                    if a.block_pattern == b.block_pattern and a.block_pattern:
                        findings.append(
                            f"Duplicate pattern across rules '{a.name}' (prio={a.priority:.2f}) "
                            f"and '{b.name}' (prio={b.priority:.2f})."
                        )
                    elif a.priority > b.priority and a.action == GuardAction.BLOCK:
                        findings.append(
                            f"Rule '{a.name}' (BLOCK, prio={a.priority:.2f}) may pre-empt "
                            f"downstream rule '{b.name}' ({b.action.value}, prio={b.priority:.2f})."
                        )

        probe_key = (
            "check_path_resolution"
            if "path" in target_name
            else "check_command_tokenization"
        )
        candidates = RuleDiagnostics.BYPASS_CANDIDATES.get(probe_key, [])
        for rule in enabled_rules:
            if not rule.block_pattern:
                continue
            try:
                rx = re.compile(rule.block_pattern, re.IGNORECASE)
            except re.error:
                continue
            uncaught = [c for c in candidates if not rx.search(c)]
            if uncaught:
                findings.append(
                    f"Rule '{rule.name}' does not match variant candidates {uncaught}."
                )
        return findings


class NVDClient:
    def __init__(
        self,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        api_key: Optional[str] = None,
        timeout: int = 20,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.api_key = api_key.strip() if api_key else None
        self.timeout = max(3, int(timeout))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, cve_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", cve_id.upper())
        return self.cache_dir / f"{safe}.json"

    def is_cached(self, cve_id: str) -> bool:
        normalized = cve_id.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            return False
        cache_file = self._cache_path(normalized)
        if not cache_file.exists():
            return False
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            return isinstance(cached, dict) and bool(cached.get("id"))
        except (OSError, json.JSONDecodeError):
            return False

    def fetch_cve_json(self, cve_id: str, force_download: bool = False) -> dict[str, Any]:
        normalized = cve_id.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
            raise ValueError("Enter a CVE ID in the format CVE-YYYY-NNNN.")
        cache_file = self._cache_path(normalized)

        if cache_file.exists() and not force_download:
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if isinstance(cached, dict) and cached.get("id"):
                    return cached
            except (OSError, json.JSONDecodeError):
                pass

        url = f"{NVD_CVE_API_URL}?{urlencode({'cveId': normalized})}"
        headers = {"User-Agent": "CVE-Flaw-Checker-TestBench/6.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        request = Request(url, headers=headers)

        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = (
                "NVD rate limit reached (HTTP 429). Set NVD_API_KEY to increase limits."
                if exc.code == 429
                else f"NVD returned HTTP {exc.code}."
            )
            raise RuntimeError(detail) from exc
        except URLError as exc:
            raise RuntimeError(f"Network error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError("NVD request timed out.") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError("NVD returned invalid JSON.") from exc

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            raise ValueError(f"NVD did not return a record for {normalized}.")
        record = vulnerabilities[0].get("cve", {})
        if not isinstance(record, dict) or not record.get("id"):
            raise ValueError("NVD response did not contain a valid CVE record.")

        try:
            cache_file.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError:
            pass
        return record

    @staticmethod
    def extract_severity(cve: dict[str, Any]) -> Severity:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(key) or []:
                data = entry.get("cvssData") or {}
                rating = (
                    data.get("baseSeverity") or entry.get("baseSeverity") or ""
                ).upper()
                if rating in Severity.__members__:
                    return Severity[rating]
                score = data.get("baseScore")
                if isinstance(score, (int, float)):
                    if score >= 9:
                        return Severity.CRITICAL
                    if score >= 7:
                        return Severity.HIGH
                    if score >= 4:
                        return Severity.MEDIUM
                    return Severity.LOW
        return Severity.HIGH

    @staticmethod
    def extract_description(cve: dict[str, Any]) -> str:
        for item in cve.get("descriptions") or []:
            if item.get("lang") == "en":
                return (item.get("value") or "").strip()
        return "No English description supplied by NVD."

    @staticmethod
    def infer_probe(description: str) -> tuple[str, str]:
        text = description.lower()
        if "path traversal" in text or "directory traversal" in text:
            return "check_path_resolution", PATH_TRAVERSAL_PATTERN
        if "command injection" in text or "os command" in text:
            return "check_command_tokenization", COMMAND_CHAINING_PATTERN
        return "manual_review", ""

    def to_flaw_record(self, cve_id: str, force_download: bool = False) -> FlawRecord:
        obj = self.fetch_cve_json(cve_id, force_download)
        description = self.extract_description(obj)
        probe, pattern = self.infer_probe(description)
        refs = obj.get("references") or []
        source = next((r.get("url") for r in refs if r.get("url")), None)
        title = description.split(".")[0][:100] or obj.get("id", cve_id)
        return FlawRecord(
            obj["id"],
            title,
            self.extract_severity(obj),
            probe,
            pattern,
            description,
            source,
        )


def atomic_write_json(path: Path, payload: Any) -> None:
    """Write JSON transactionally so an interrupted save does not truncate state."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


@dataclass(frozen=True)
class PredictiveAssessment:
    """Explainable triage estimate; not proof that a host is vulnerable."""
    priority_score: float
    confidence: float
    tier: str
    reasons: tuple[str, ...]


class PredictiveTriageEngine:
    """
    Deterministic, explainable prioritizer. It combines CVSS severity, available
    probe coverage, and exploit-related language. It deliberately does NOT claim
    host applicability because this application has no software/CPE inventory.
    """

    EXPLOIT_TERMS = (
        "remote code execution", "arbitrary code execution", "unauthenticated",
        "network reachable", "network attack", "privilege escalation",
        "authentication bypass", "actively exploited", "in the wild",
    )

    @classmethod
    def assess(cls, flaw: FlawRecord, learned_weight: float = 1.0) -> PredictiveAssessment:
        severity_points = {
            Severity.LOW: 18.0, Severity.MEDIUM: 42.0,
            Severity.HIGH: 72.0, Severity.CRITICAL: 92.0,
        }[flaw.severity]
        description = flaw.description.lower()
        hits = [term for term in cls.EXPLOIT_TERMS if term in description]
        exploit_bonus = min(24.0, len(hits) * 6.0)
        probe_bonus = 8.0 if flaw.probe_name in PROBES else 0.0
        weight_factor = max(0.75, min(1.25, float(learned_weight)))
        score = min(100.0, (severity_points + exploit_bonus + probe_bonus) * weight_factor)

        # Confidence is confidence in this triage classification, not in host exposure.
        confidence = 0.45
        if flaw.probe_name in PROBES:
            confidence += 0.20
        if flaw.description and len(flaw.description) >= 80:
            confidence += 0.10
        if hits:
            confidence += min(0.15, len(hits) * 0.03)
        confidence = min(0.90, confidence)

        tier = "URGENT" if score >= 85 else "HIGH" if score >= 65 else (
            "MODERATE" if score >= 40 else "LOW"
        )
        reasons = [f"NVD severity contributes {severity_points:.0f}/100 base points."]
        if hits:
            reasons.append("Exploit-related indicators: " + ", ".join(hits[:5]) + ".")
        else:
            reasons.append("No configured exploit-language indicators were found.")
        reasons.append(
            "Automated probe coverage is available." if probe_bonus
            else "No automated probe exists; manual validation is required."
        )
        reasons.append(
            "Learned weight adjusts triage priority only; it does not prove applicability."
        )
        return PredictiveAssessment(round(score, 1), round(confidence, 2), tier, tuple(reasons))


# Live test-bench targets (no OS command execution; sandboxed path resolution)
weight_store = LearningWeightStore()
registry = GuardRegistry(weights=weight_store)
rollback_ledger = RollbackLedger()


def ensure_sandbox_dir(sandbox_dir: Path = DEFAULT_SANDBOX_DIR) -> Path:
    root = Path(sandbox_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sample = root / "bench_manifest.json"
    if not sample.exists():
        sample.write_text(
            json.dumps({"bench": "active", "status": "ok"}, indent=2), encoding="utf-8"
        )
    return root


@registry.protect
def resolve_bench_path(
    relative_path: str, sandbox_dir: Path = DEFAULT_SANDBOX_DIR
) -> Path:
    """Resolve a candidate path strictly inside the configured sandbox directory."""
    root = ensure_sandbox_dir(sandbox_dir)
    cleaned = relative_path.lstrip("/\\")
    candidate = (root / cleaned).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PathEscapeError(
            f"Path escapes sandbox root ({root}): {relative_path}"
        ) from exc
    return candidate


@registry.protect
def parse_bench_command_tokens(command_line: str) -> list[str]:
    """Parse a command line into argv tokens safely without invoking a shell."""
    tokens = shlex.split(command_line, posix=(os.name != "nt"))
    return tokens


def check_path_resolution(target: Callable[..., Any]) -> Optional[str]:
    """Check whether a target accepts a traversal-shaped input without blocking/escaping."""
    candidate = "../outside-bench/target.conf"
    try:
        resolved = target(candidate)
    except GuardBlockedError as exc:
        return f"Guard intercepted traversal input ({exc.event.guard_name})."
    except PathEscapeError as exc:
        return f"Target rejected escape path ({exc})."
    except Exception as exc:
        return f"Target raised {type(exc).__name__}: {exc}"

    if isinstance(resolved, Path):
        root = ensure_sandbox_dir()
        try:
            resolved.resolve().relative_to(root)
            return (
                f"Target resolved '{candidate}' inside sandbox -> {resolved} "
                "(verify guard or canonicalization policy)."
            )
        except ValueError:
            return f"Target resolved outside sandbox -> {resolved}"
    return f"Target returned non-path result for '{candidate}': {resolved!r}"


def check_command_tokenization(target: Callable[..., Any]) -> Optional[str]:
    """Check whether command chaining metacharacters appear in tokenized input."""
    sample_cmd = "status --verbose; echo check_token"
    try:
        tokens = target(sample_cmd)
    except GuardBlockedError as exc:
        return f"Guard intercepted command chaining input ({exc.event.guard_name})."
    except Exception as exc:
        return f"Target raised {type(exc).__name__}: {exc}"

    if isinstance(tokens, list) and any(
        re.search(COMMAND_CHAINING_PATTERN, tok) for tok in tokens
    ):
        return (
            f"Tokenized output contains shell operator tokens from '{sample_cmd}': "
            f"{tokens}"
        )
    return None


PROBES: dict[str, Callable[[Callable[..., Any]], Optional[str]]] = {
    "check_path_resolution": check_path_resolution,
    "check_command_tokenization": check_command_tokenization,
}


def _iter_string_inputs(args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[str]:
    strings: list[str] = []

    def collect(val: Any) -> None:
        if isinstance(val, str):
            strings.append(val)
        elif isinstance(val, (list, tuple)):
            for item in val:
                collect(item)
        elif isinstance(val, dict):
            for item in val.values():
                collect(item)

    for arg in args:
        collect(arg)
    for val in kwargs.values():
        collect(val)
    return strings


class FlawGuardController:
    def __init__(
        self,
        registry: GuardRegistry,
        catalog: list[FlawRecord],
        weights: Optional[LearningWeightStore] = None,
        ledger: Optional[RollbackLedger] = None,
    ) -> None:
        self.registry = registry
        self.catalog = catalog
        self.weights = weights or registry.weights or LearningWeightStore()
        self.ledger = ledger

    def check_targets(
        self, *targets: Callable[..., Any], trace: Optional[ReasoningTrace] = None
    ) -> list[FlawMatch]:
        matches: list[FlawMatch] = []
        for target in targets:
            for flaw in self.catalog:
                probe = PROBES.get(flaw.probe_name)
                w = self.weights.get_weight(
                    flaw.flaw_id, target.__name__, flaw.probe_name
                )
                if not probe:
                    if trace:
                        trace.add(
                            "Observation",
                            f"No automated probe for {flaw.flaw_id} (probe={flaw.probe_name}); "
                            f"weight={w:.2f}, flagged for manual review.",
                        )
                    continue
                evidence = probe(target)
                if evidence:
                    new_w, delta = self.weights.update_weight(
                        flaw.flaw_id,
                        target.__name__,
                        flaw.probe_name,
                        +0.15,
                        "Matched probe check on test bench",
                    )
                    matches.append(FlawMatch(target.__name__, flaw, evidence))
                    if trace:
                        trace.add(
                            "Observation",
                            f"Match on {target.__name__} for {flaw.flaw_id} "
                            f"(severity={flaw.severity.value.upper()}, weight={new_w:.2f}): {evidence}",
                            weight_delta=delta,
                        )
                else:
                    new_w, delta = self.weights.update_weight(
                        flaw.flaw_id,
                        target.__name__,
                        flaw.probe_name,
                        -0.05,
                        "No match observed on test bench",
                    )
                    if trace:
                        trace.add(
                            "Observation",
                            f"No match on {target.__name__} for {flaw.flaw_id} "
                            f"(weight={new_w:.2f}).",
                            weight_delta=delta,
                        )
        return matches

    def choose_action_with_reasoning(
        self, match: FlawMatch, trace: Optional[ReasoningTrace] = None
    ) -> tuple[GuardAction, float]:
        w = self.weights.get_weight(
            match.flaw.flaw_id, match.target_name, match.flaw.probe_name
        )
        prediction = PredictiveTriageEngine.assess(match.flaw, w)
        if trace:
            trace.add(
                "Predictive Triage",
                f"Priority={prediction.priority_score:.1f}/100 "
                f"({prediction.tier}); triage confidence={prediction.confidence:.0%}. "
                + " ".join(prediction.reasons),
            )
        sev_score = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.45,
            Severity.LOW: 0.2,
        }[match.flaw.severity]
        effective_score = round(sev_score * w, 4)

        if (
            match.flaw.severity in (Severity.CRITICAL, Severity.HIGH)
            or effective_score >= 0.7
        ):
            action = GuardAction.BLOCK
        elif effective_score >= 0.35:
            action = GuardAction.SANITIZE
        else:
            action = GuardAction.AUDIT

        if trace:
            trace.add(
                "Reasoning & Weighting",
                f"Computed effective_score={effective_score:.3f} "
                f"(severity={match.flaw.severity.value}, weight={w:.2f}) -> "
                f"selected action={action.value.upper()}.",
            )
        return action, effective_score

    def apply_guards(
        self,
        matches: list[FlawMatch],
        action: Optional[GuardAction] = None,
        sanitizer: Optional[Callable[[str], str]] = None,
        trace: Optional[ReasoningTrace] = None,
        checkpoint_label: Optional[str] = None,
    ) -> int:
        posted = 0
        for match in matches:
            if not match.flaw.block_pattern:
                if trace:
                    trace.add(
                        "Remediation",
                        f"Skipped {match.flaw.flaw_id} on {match.target_name}: no pattern defined.",
                    )
                continue
            try:
                compiled = re.compile(match.flaw.block_pattern, re.IGNORECASE)
            except re.error:
                continue

            chosen_action, priority = (
                (
                    action,
                    self.weights.get_weight(
                        match.flaw.flaw_id, match.target_name, match.flaw.probe_name
                    ),
                )
                if action is not None
                else self.choose_action_with_reasoning(match, trace=trace)
            )
            effective_sanitizer = sanitizer or (
                RemediationEngine.build_sanitizer(match.flaw)
                if chosen_action == GuardAction.SANITIZE
                else None
            )

            sim_rows = CounterfactualSimulator.simulate(
                match.flaw, match.target_name, sanitizer_fn=effective_sanitizer
            )
            if trace:
                matched_count = sum(1 for r in sim_rows if r["matched"] == "yes")
                trace.add(
                    "Counterfactual Sim",
                    f"Simulated {len(sim_rows)} test inputs ({matched_count} pattern matches) "
                    f"for {match.target_name} under {chosen_action.value.upper()}.",
                )

            def predicate(*args: Any, _regex=compiled, **kwargs: Any) -> bool:
                return any(
                    bool(_regex.search(candidate))
                    for candidate in _iter_string_inputs(args, kwargs)
                )

            verb = (
                "Blocked"
                if chosen_action == GuardAction.BLOCK
                else ("Sanitized" if chosen_action == GuardAction.SANITIZE else "Audited")
            )
            self.registry.register(
                GuardRule(
                    name=f"{chosen_action.value}_{match.flaw.flaw_id.lower()}",
                    target_name=match.target_name,
                    predicate=predicate,
                    action=chosen_action,
                    flaw_id=match.flaw.flaw_id,
                    reason=f"{verb} input matching pattern for {match.flaw.flaw_id}",
                    priority=priority,
                    block_pattern=match.flaw.block_pattern,
                    sanitizer=effective_sanitizer,
                )
            )
            posted += 1

            diagnostics = RuleDiagnostics.analyze_target(
                match.target_name, self.registry.rules_for(match.target_name)
            )
            if trace:
                trace.add(
                    "Fix Applied",
                    f"Registered {chosen_action.value.upper()} guard on {match.target_name} "
                    f"for {match.flaw.flaw_id} (priority={priority:.2f}).",
                )
                for diag in diagnostics:
                    trace.add("Rule Diagnostics", diag)

        if posted > 0 and self.ledger is not None:
            cp = self.ledger.record_checkpoint(
                label=checkpoint_label
                or f"Applied {posted} rule(s) ({action.value if action else 'auto'})",
                weights_snapshot=self.weights.snapshot(),
                rule_specs=self.registry.export_rule_specs(),
            )
            if trace:
                trace.add(
                    "Ledger Checkpoint",
                    f"Recorded {cp.checkpoint_id} [hash={cp.entry_hash[:12]}...].",
                )
        return posted


class CVEBenchApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1220x820")
        self.minsize(920, 620)
        self.configure(bg="#111827")

        ensure_sandbox_dir()
        self.events: Queue = Queue()
        self._stop_auto = Event()
        self._auto_running = False
        self._run_counter = 0
        self._run_counter_lock = Lock()
        self.catalog: list[FlawRecord] = []
        self.last_matches: list[FlawMatch] = []
        self.traces: list[ReasoningTrace] = []
        self.batch_outcomes: list[CveBatchOutcome] = []
        env_key = os.environ.get("NVD_API_KEY", "").strip() or None
        self.client = NVDClient(api_key=env_key)
        self._build_ui()
        self.after(120, self._poll_events)
        self._log(
            "Test bench initialized with batch CVE queue, per-CVE outcomes, "
            "counterfactual simulation, rollback ledger, learning weights & reasoning traces."
        )
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _next_run_id(self) -> str:
        with self._run_counter_lock:
            self._run_counter += 1
            return f"RUN-{self._run_counter:04d}"

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#111827")
        style.configure("TLabel", background="#111827", foreground="#e5e7eb")
        style.configure("TCheckbutton", background="#111827", foreground="#e5e7eb")
        style.configure(
            "Title.TLabel", font=("Segoe UI", 17, "bold"), foreground="#f9fafb"
        )
        style.configure("TButton", padding=7)
        style.configure(
            "Treeview",
            rowheight=26,
            background="#1f2937",
            fieldbackground="#1f2937",
            foreground="#f9fafb",
        )
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        header = ttk.Frame(self, padding=(16, 14))
        header.pack(fill="x")
        ttk.Label(header, text="CVE TEST BENCH WORKBENCH", style="Title.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            header,
            text="Live NVD 2.0 • batch queue • bench targets • guards • counterfactual sim • rollback ledger • weights • AI Automatic",
        ).pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self, padding=(16, 5))
        controls.pack(fill="x")
        ttk.Label(controls, text="CVE ID(s)").pack(side="left")
        self.cve_var = tk.StringVar(value="CVE-2021-41773")
        entry = ttk.Entry(controls, textvariable=self.cve_var, width=34)
        entry.pack(side="left", padx=(8, 10))
        entry.bind("<Return>", lambda _e: self.fetch_selected())

        self.fetch_btn = ttk.Button(
            controls, text="Fetch CVE", command=self.fetch_selected
        )
        self.fetch_btn.pack(side="left")

        self.refresh_btn = ttk.Button(
            controls,
            text="Refresh from NVD",
            command=lambda: self.fetch_selected(True),
        )
        self.refresh_btn.pack(side="left", padx=6)

        self.ai_auto_btn = ttk.Button(
            controls, text="AI Automatic", command=self.toggle_ai_automatic
        )
        self.ai_auto_btn.pack(side="left", padx=(6, 0))

        self.loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls, text="Auto-repeat (30s)", variable=self.loop_var
        ).pack(side="left", padx=(8, 4))

        # Safe-by-default: autonomous analysis never changes guard policy unless
        # the operator explicitly enables this option.
        self.auto_apply_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="Allow auto-install guards",
            variable=self.auto_apply_var,
        ).pack(side="left", padx=(8, 4))

        ttk.Button(controls, text="Cache folder", command=self.open_cache_folder).pack(
            side="right"
        )

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.status_var, padding=(16, 4)).pack(fill="x")
        ttk.Label(
            self,
            text="Predictive scores prioritize investigation; verify installed product, "
                 "version, configuration and vendor advisories before treating a CVE as applicable.",
            foreground="#fbbf24",
            wraplength=1160,
        ).pack(fill="x", padx=16, pady=(0, 4))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=8)
        catalog_tab = ttk.Frame(notebook, padding=10)
        detail_tab = ttk.Frame(notebook, padding=10)
        guard_tab = ttk.Frame(notebook, padding=10)
        outcomes_tab = ttk.Frame(notebook, padding=10)
        reasoning_tab = ttk.Frame(notebook, padding=10)
        ledger_tab = ttk.Frame(notebook, padding=10)
        events_tab = ttk.Frame(notebook, padding=10)
        log_tab = ttk.Frame(notebook, padding=10)
        notebook.add(catalog_tab, text="CVE Catalog")
        notebook.add(detail_tab, text="CVE Details")
        notebook.add(guard_tab, text="Test Bench & Guards")
        notebook.add(outcomes_tab, text="Batch Outcomes")
        notebook.add(reasoning_tab, text="Reasoning & Weights")
        notebook.add(ledger_tab, text="Counterfactual & Ledger")
        notebook.add(events_tab, text="Guard Events")
        notebook.add(log_tab, text="Activity Log")

        self.tree = ttk.Treeview(
            catalog_tab, columns=("severity", "probe", "title"), show="headings", height=12
        )
        for col, heading, width in (
            ("severity", "Severity", 100),
            ("probe", "Suggested check", 210),
            ("title", "Description summary", 720),
        ):
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._show_selected)

        self.details = tk.Text(
            detail_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            insertbackground="white",
            relief="flat",
            padx=12,
            pady=12,
        )
        self.details.pack(fill="both", expand=True)
        self.details.insert("1.0", "Fetch a CVE to view its NVD description and metadata.")
        self.details.configure(state="disabled")

        ttk.Label(
            guard_tab, text="Live Test-Bench Targets & Guards", style="Title.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            guard_tab,
            text=(
                "Evaluates and guards resolve_bench_path() and parse_bench_command_tokens() "
                "using @registry.protect rules (BLOCK, SANITIZE, AUDIT)."
            ),
            wraplength=1080,
        ).pack(anchor="w", pady=6)

        buttons = ttk.Frame(guard_tab)
        buttons.pack(anchor="w", pady=6)
        ttk.Button(buttons, text="Run bench checks", command=self.run_bench_checks).pack(
            side="left"
        )
        ttk.Button(
            buttons,
            text="Install BLOCK guards",
            command=lambda: self.install_guards(GuardAction.BLOCK),
        ).pack(side="left", padx=6)
        ttk.Button(
            buttons,
            text="Install SANITIZE guards",
            command=lambda: self.install_guards(GuardAction.SANITIZE),
        ).pack(side="left", padx=6)
        ttk.Button(
            buttons, text="Verify guarded targets", command=self.verify_guards
        ).pack(side="left", padx=6)

        self.match_text = tk.Text(
            guard_tab,
            height=12,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.match_text.pack(fill="both", expand=True, pady=(10, 0))

        outcome_buttons = ttk.Frame(outcomes_tab)
        outcome_buttons.pack(fill="x")
        ttk.Button(
            outcome_buttons,
            text="Refresh outcomes",
            command=self.refresh_outcomes_view,
        ).pack(side="left")
        ttk.Button(
            outcome_buttons,
            text="Export outcomes JSON",
            command=self.export_outcomes_json,
        ).pack(side="left", padx=6)
        ttk.Button(
            outcome_buttons,
            text="Clear outcomes",
            command=self.clear_outcomes_view,
        ).pack(side="left", padx=6)

        self.outcomes_tree = ttk.Treeview(
            outcomes_tab,
            columns=("run", "cve", "status", "severity", "action", "summary"),
            show="headings",
            height=14,
        )
        for col, heading, width in (
            ("run", "Run", 90),
            ("cve", "CVE ID", 150),
            ("status", "Outcome", 150),
            ("severity", "Severity", 95),
            ("action", "Guard Action", 115),
            ("summary", "Per-CVE details", 520),
        ):
            self.outcomes_tree.heading(col, text=heading)
            self.outcomes_tree.column(col, width=width, anchor="w")
        self.outcomes_tree.pack(fill="both", expand=True, pady=(8, 0))

        reason_buttons = ttk.Frame(reasoning_tab)
        reason_buttons.pack(fill="x")
        ttk.Button(
            reason_buttons,
            text="Refresh traces & weights",
            command=self.refresh_reasoning_view,
        ).pack(side="left")
        ttk.Button(
            reason_buttons,
            text="Reset learned weights",
            command=self.reset_weights_view,
        ).pack(side="left", padx=6)

        self.reasoning_text = tk.Text(
            reasoning_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.reasoning_text.pack(fill="both", expand=True, pady=(8, 0))

        ledger_controls = ttk.Frame(ledger_tab)
        ledger_controls.pack(fill="x")
        ttk.Button(
            ledger_controls,
            text="Simulate counterfactuals & diagnostics",
            command=self.run_counterfactual_and_diagnostics,
        ).pack(side="left")
        ttk.Button(
            ledger_controls,
            text="Verify hash chain",
            command=self.verify_ledger_chain,
        ).pack(side="left", padx=6)
        ttk.Label(ledger_controls, text="Checkpoint ID:").pack(side="left", padx=(12, 4))
        self.cp_var = tk.StringVar(value="CP-0001")
        ttk.Entry(ledger_controls, textvariable=self.cp_var, width=12).pack(
            side="left"
        )
        ttk.Button(
            ledger_controls,
            text="Rollback to checkpoint",
            command=self.rollback_to_checkpoint,
        ).pack(side="left", padx=6)

        self.ledger_text = tk.Text(
            ledger_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.ledger_text.pack(fill="both", expand=True, pady=(8, 0))

        event_buttons = ttk.Frame(events_tab)
        event_buttons.pack(fill="x")
        ttk.Button(
            event_buttons, text="Refresh events", command=self.refresh_events_view
        ).pack(side="left")
        ttk.Button(
            event_buttons, text="Export events JSON", command=self.export_events_json
        ).pack(side="left", padx=6)
        ttk.Button(
            event_buttons, text="Clear events", command=self.clear_events_view
        ).pack(side="left", padx=6)

        self.events_text = tk.Text(
            events_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.events_text.pack(fill="both", expand=True, pady=(8, 0))

        log_buttons = ttk.Frame(log_tab)
        log_buttons.pack(fill="x")
        ttk.Button(log_buttons, text="Clear log", command=self.clear_log).pack(
            side="left"
        )
        self.log_text = tk.Text(
            log_tab,
            wrap="word",
            bg="#0b1220",
            fg="#d1d5db",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.log_text.pack(fill="both", expand=True, pady=(8, 0))

        footer = ttk.Frame(self, padding=(16, 6))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="NVD data is informational; confirm affected versions and configurations on your system.",
            foreground="#9ca3af",
        ).pack(side="left")

    def _log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{stamp}] {message}\n")
        self.log_text.see("end")

    def clear_log(self) -> None:
        self.log_text.delete("1.0", "end")

    def _set_busy(self, busy: bool, message: str) -> None:
        self.status_var.set(message)
        state = "disabled" if busy else "normal"
        self.fetch_btn.configure(state=state)
        self.refresh_btn.configure(state=state)
        if not self._auto_running:
            self.ai_auto_btn.configure(state=state)

    def _record_trace(self, trace: ReasoningTrace) -> None:
        self.traces.append(trace)
        self.refresh_reasoning_view()

    def _record_outcome(self, outcome: CveBatchOutcome) -> None:
        self.batch_outcomes.append(outcome)
        self.refresh_outcomes_view()

    def toggle_ai_automatic(self) -> None:
        if self._auto_running:
            self._stop_auto.set()
            self._log("AI Automatic stop requested...")
            return

        cve_queue = parse_cve_queue(self.cve_var.get())
        if not cve_queue:
            cve_queue = ["CVE-2021-41773"]

        repeat_enabled = bool(self.loop_var.get())
        allow_auto_apply = bool(self.auto_apply_var.get())
        self._stop_auto.clear()
        self._auto_running = True
        self.ai_auto_btn.configure(text="Stop AI Auto")
        self.fetch_btn.configure(state="disabled")
        self.refresh_btn.configure(state="disabled")
        self._log(
            f"AI Automatic started for batch queue ({len(cve_queue)} CVE(s)): "
            f"{', '.join(cve_queue)}"
        )

        def autonomous_worker() -> None:
            try:
                while not self._stop_auto.is_set():
                    # Tkinter variables/widgets are UI-thread-only. Use immutable
                    # snapshots captured before the worker was launched.
                    current_queue = cve_queue
                    for idx, target_cve in enumerate(current_queue):
                        if self._stop_auto.is_set():
                            break
                        run_id = self._next_run_id()
                        ts = datetime.now(timezone.utc).isoformat()
                        trace = ReasoningTrace(
                            run_id=run_id,
                            timestamp=ts,
                            cve_id=target_cve,
                            mode="AI Automatic Batch",
                        )
                        self.events.put(
                            (
                                "status",
                                f"AI Auto [{idx + 1}/{len(current_queue)}] {target_cve}...",
                            )
                        )
                        self.events.put(
                            (
                                "log",
                                f"[AI Auto {run_id}] [{idx + 1}/{len(current_queue)}] "
                                f"Processing {target_cve}...",
                            )
                        )

                        was_cached = self.client.is_cached(target_cve)
                        try:
                            record = self.client.to_flaw_record(
                                target_cve, force_download=False
                            )
                        except Exception as exc:
                            err_msg = str(exc)
                            trace.add("CVE Ingestion", f"Failed to load {target_cve}: {err_msg}")
                            trace.final_decision = f"ERROR: {err_msg}"
                            self.events.put(("trace", trace))
                            outcome = CveBatchOutcome(
                                run_id=run_id,
                                timestamp=ts,
                                cve_id=target_cve,
                                status="ERROR",
                                severity="N/A",
                                probe_name="N/A",
                                action_taken="NONE",
                                matches_count=0,
                                summary=err_msg,
                            )
                            self.events.put(("outcome", outcome))
                            self.events.put(
                                ("log", f"[AI Auto {run_id}] {target_cve} ERROR: {err_msg}")
                            )
                            continue

                        if not was_cached and not self.client.api_key and idx + 1 < len(current_queue):
                            # Polite pacing for unauthenticated NVD requests between uncached fetches.
                            for _ in range(60):
                                if self._stop_auto.is_set():
                                    break
                                self._stop_auto.wait(0.1)
                            if self._stop_auto.is_set():
                                break

                        trace.add(
                            "CVE Ingestion",
                            f"Loaded {record.flaw_id} (severity={record.severity.value.upper()}, "
                            f"probe={record.probe_name}).",
                        )
                        self.events.put(("record", record))

                        working_catalog = [
                            r for r in self.catalog if r.flaw_id != record.flaw_id
                        ] + [record]
                        controller = FlawGuardController(
                            registry,
                            working_catalog,
                            weights=weight_store,
                            ledger=rollback_ledger,
                        )
                        matches = controller.check_targets(
                            resolve_bench_path, parse_bench_command_tokens, trace=trace
                        )
                        self.events.put(("matches", matches))

                        installed_total = 0
                        actions_applied: list[str] = []
                        if allow_auto_apply:
                            for match in matches:
                                if self._stop_auto.is_set():
                                    break
                                chosen_action, _score = controller.choose_action_with_reasoning(
                                    match, trace=trace
                                )
                                added = controller.apply_guards(
                                    [match],
                                    action=chosen_action,
                                    trace=trace,
                                    checkpoint_label=f"{run_id} {match.flaw.flaw_id} -> {chosen_action.value}",
                                )
                                installed_total += added
                                actions_applied.append(
                                    f"{chosen_action.value.upper()}@{match.target_name}"
                                )
                        elif matches:
                            trace.add(
                                "Safety Gate",
                                "Analysis-only mode: findings were assessed but no guards "
                                "were installed. Enable 'Allow auto-install guards' to permit "
                                "autonomous policy changes.",
                            )

                        if installed_total > 0:
                            status = "APPLIED_GUARD"
                            action_str = ", ".join(actions_applied)
                            summary = (
                                f"{len(matches)} match(es); applied {installed_total} rule(s) "
                                f"({action_str})."
                            )
                        elif matches and not allow_auto_apply:
                            status = "ANALYSIS_ONLY"
                            action_str = "NOT INSTALLED"
                            summary = (
                                f"{len(matches)} potential finding(s) reviewed; "
                                "automatic guard installation is disabled."
                            )
                        elif record.probe_name == "manual_review":
                            status = "MANUAL_REVIEW"
                            action_str = "NONE"
                            summary = (
                                "No automated probe signature; flagged for manual review."
                            )
                        else:
                            status = "NO_PROBE_MATCH"
                            action_str = "NONE"
                            summary = (
                                f"Probe '{record.probe_name}' reported no bench match."
                            )

                        trace.final_decision = f"[{status}] {summary}"
                        self.events.put(("trace", trace))

                        outcome = CveBatchOutcome(
                            run_id=run_id,
                            timestamp=ts,
                            cve_id=record.flaw_id,
                            status=status,
                            severity=record.severity.value.upper(),
                            probe_name=record.probe_name,
                            action_taken=action_str,
                            matches_count=len(matches),
                            summary=summary,
                        )
                        self.events.put(("outcome", outcome))
                        self.events.put(
                            (
                                "log",
                                f"[AI Auto {run_id}] Outcome {record.flaw_id}: "
                                f"status={status} | {summary}",
                            )
                        )
                        if installed_total > 0:
                            self.events.put(("verify_silent", None))

                    if not repeat_enabled:
                        break

                    for _ in range(300):
                        if self._stop_auto.is_set():
                            break
                        self._stop_auto.wait(0.1)
            except Exception as exc:
                self.events.put(("error", f"AI Automatic stopped: {exc}"))
            finally:
                self.events.put(("auto_done", None))

        Thread(target=autonomous_worker, daemon=True).start()

    def fetch_selected(self, force: bool = False) -> None:
        cve_queue = parse_cve_queue(self.cve_var.get())
        if not cve_queue:
            messagebox.showwarning("CVE required", "Enter at least one CVE ID first.")
            return
        self._set_busy(True, f"Loading {len(cve_queue)} CVE(s)…")
        self._log(
            f"Loading {', '.join(cve_queue)} "
            f"{'from NVD' if force else 'from cache/NVD'}."
        )

        def worker() -> None:
            try:
                for idx, cve_id in enumerate(cve_queue):
                    record = self.client.to_flaw_record(cve_id, force_download=force)
                    self.events.put(("record", record))
                    if force and not self.client.api_key and idx + 1 < len(cve_queue):
                        Event().wait(6.0)
                self.events.put(("busy_done", None))
            except Exception as exc:
                self.events.put(("error", str(exc)))
                self.events.put(("busy_done", None))

        Thread(target=worker, daemon=True).start()

    def _render_matches(self, matches: list[FlawMatch]) -> None:
        self.last_matches = matches
        self.match_text.delete("1.0", "end")
        if not matches:
            self.match_text.insert("end", "No test-bench matches were reported.\n")
            return
        for match in matches:
            w = weight_store.get_weight(
                match.flaw.flaw_id, match.target_name, match.flaw.probe_name
            )
            self.match_text.insert(
                "end",
                f"{match.flaw.flaw_id} → {match.target_name} [weight={w:.2f}]\n"
                f"{match.evidence}\n\n",
            )

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "log":
                    self._log(str(payload))
                elif kind == "record":
                    record: FlawRecord = payload
                    existing = next(
                        (
                            i
                            for i, item in enumerate(self.catalog)
                            if item.flaw_id == record.flaw_id
                        ),
                        None,
                    )
                    if existing is None:
                        self.catalog.append(record)
                    else:
                        self.catalog[existing] = record
                    self._refresh_catalog()
                    self._display_record(record)
                    self._log(
                        f"Loaded {record.flaw_id} ({record.severity.value.upper()})."
                    )
                elif kind == "matches":
                    self._render_matches(payload)
                elif kind == "outcome":
                    self._record_outcome(payload)
                elif kind == "trace":
                    self._record_trace(payload)
                elif kind == "verify_silent":
                    self._verify_guards_silently(reinforce_matches=True)
                    self.refresh_events_view()
                    self.refresh_reasoning_view()
                    self.run_counterfactual_and_diagnostics()
                elif kind == "busy_done":
                    self._set_busy(False, "Idle")
                elif kind == "auto_done":
                    self._auto_running = False
                    self._stop_auto.clear()
                    self.ai_auto_btn.configure(text="AI Automatic", state="normal")
                    self._set_busy(False, "Idle")
                    self._log("AI Automatic idle.")
                elif kind == "error":
                    self._log(f"ERROR: {payload}")
                    if not self._auto_running:
                        messagebox.showerror("CVE load failed", str(payload))
        except Empty:
            pass
        if self.winfo_exists():
            self.after(120, self._poll_events)

    def _refresh_catalog(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for record in self.catalog:
            self.tree.insert(
                "",
                "end",
                iid=record.flaw_id,
                values=(record.severity.value.upper(), record.probe_name, record.title),
            )

    def _show_selected(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        record = next((x for x in self.catalog if x.flaw_id == selected[0]), None)
        if record:
            self._display_record(record)

    def _display_record(self, record: FlawRecord) -> None:
        text = (
            f"{record.flaw_id}\n"
            f"Severity: {record.severity.value.upper()}\n"
            f"Suggested check: {record.probe_name}\n"
            f"Suggested pattern: "
            f"{record.block_pattern or 'No automatic pattern — manual review required'}\n"
            f"Title: {record.title}\n\n"
            f"Description:\n{record.description}\n\n"
            f"NVD reference: {record.source_url or 'Not supplied'}\n\n"
            "Note: Validate affected product versions and configurations on your test bench."
        )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def refresh_outcomes_view(self) -> None:
        for item in self.outcomes_tree.get_children():
            self.outcomes_tree.delete(item)
        for idx, out in enumerate(self.batch_outcomes):
            self.outcomes_tree.insert(
                "",
                "end",
                iid=f"out_{idx}",
                values=(
                    out.run_id,
                    out.cve_id,
                    out.status,
                    out.severity,
                    out.action_taken,
                    out.summary,
                ),
            )

    def clear_outcomes_view(self) -> None:
        self.batch_outcomes.clear()
        self.refresh_outcomes_view()
        self._log("Cleared recorded batch outcomes.")

    def export_outcomes_json(self) -> None:
        if not self.batch_outcomes:
            messagebox.showinfo("No outcomes", "No batch outcomes to export.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="batch_outcomes.json",
        )
        if not file_path:
            return
        serializable = [
            {
                "run_id": o.run_id,
                "timestamp": o.timestamp,
                "cve_id": o.cve_id,
                "status": o.status,
                "severity": o.severity,
                "probe_name": o.probe_name,
                "action_taken": o.action_taken,
                "matches_count": o.matches_count,
                "summary": o.summary,
            }
            for o in self.batch_outcomes
        ]
        atomic_write_json(Path(file_path), serializable)
        self._log(f"Exported {len(serializable)} batch outcome(s) to {file_path}.")

    def run_bench_checks(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        run_id = self._next_run_id()
        cve_label = ", ".join(r.flaw_id for r in self.catalog)
        trace = ReasoningTrace(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            cve_id=cve_label,
            mode="Manual Check",
        )
        controller = FlawGuardController(
            registry, self.catalog, weights=weight_store, ledger=rollback_ledger
        )
        matches = controller.check_targets(
            resolve_bench_path, parse_bench_command_tokens, trace=trace
        )
        trace.final_decision = f"Identified {len(matches)} bench match(es)."
        self._record_trace(trace)
        self._render_matches(matches)
        self._log(f"Test-bench checks completed [{run_id}]: {len(matches)} match(es).")

    def install_guards(self, action: GuardAction = GuardAction.BLOCK) -> None:
        if not self.last_matches:
            messagebox.showinfo(
                "Run checks first", "Run bench checks before installing guards."
            )
            return
        run_id = self._next_run_id()
        cve_label = ", ".join(sorted({m.flaw.flaw_id for m in self.last_matches}))
        trace = ReasoningTrace(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            cve_id=cve_label,
            mode=f"Install {action.value.upper()}",
        )
        count = FlawGuardController(
            registry, self.catalog, weights=weight_store, ledger=rollback_ledger
        ).apply_guards(
            self.last_matches,
            action=action,
            trace=trace,
            checkpoint_label=f"{run_id} manual {action.value}",
        )
        trace.final_decision = f"Installed {count} {action.value.upper()} rule(s)."
        self._record_trace(trace)
        self._log(
            f"Installed {count} {action.value.upper()} guard rule(s) on test-bench targets."
        )
        self.refresh_events_view()
        self.run_counterfactual_and_diagnostics()
        messagebox.showinfo(
            "Guards installed",
            f"Installed {count} {action.value.upper()} rule(s).",
        )

    def _verify_guards_silently(self, reinforce_matches: bool = False) -> list[str]:
        outcomes: list[str] = []
        path_intercepted = False
        cmd_intercepted = False

        try:
            p = resolve_bench_path("../bench_manifest.json")
            outcomes.append(f"resolve_bench_path -> {p}")
        except GuardBlockedError as exc:
            path_intercepted = True
            self._log(str(exc))
            outcomes.append(str(exc))

        try:
            tokens = parse_bench_command_tokens("status --check; verify_token")
            outcomes.append(f"parse_bench_command_tokens -> {tokens}")
        except GuardBlockedError as exc:
            cmd_intercepted = True
            self._log(str(exc))
            outcomes.append(str(exc))

        if reinforce_matches and self.last_matches:
            for match in self.last_matches:
                intercepted = (
                    path_intercepted
                    if match.target_name == "resolve_bench_path"
                    else cmd_intercepted
                )
                if intercepted:
                    weight_store.update_weight(
                        match.flaw.flaw_id,
                        match.target_name,
                        match.flaw.probe_name,
                        +0.10,
                        "Guard verified active during post-fix check",
                    )
        return outcomes

    def verify_guards(self) -> None:
        outcomes = self._verify_guards_silently(reinforce_matches=True)
        self.refresh_events_view()
        self.refresh_reasoning_view()
        messagebox.showinfo("Guard verification", "\n".join(outcomes))

    def run_counterfactual_and_diagnostics(self) -> None:
        self.ledger_text.delete("1.0", "end")
        ok, chain_msg = rollback_ledger.verify_integrity()
        self.ledger_text.insert("end", f"=== Hash-Chain Integrity ===\n{chain_msg}\n\n")

        self.ledger_text.insert("end", "=== Checkpoints ===\n")
        cps = rollback_ledger.checkpoints()
        if not cps:
            self.ledger_text.insert("end", "No ledger checkpoints recorded yet.\n\n")
        else:
            for cp in cps[-10:]:
                self.ledger_text.insert(
                    "end",
                    f"  {cp.checkpoint_id} | {cp.timestamp} | {cp.label} | "
                    f"rules={len(cp.rule_specs)} | hash={cp.entry_hash[:16]}...\n",
                )
            self.ledger_text.insert("end", "\n")

        self.ledger_text.insert("end", "=== Counterfactual Simulations ===\n")
        if not self.last_matches:
            self.ledger_text.insert(
                "end", "Run checks or AI Automatic to simulate matches.\n\n"
            )
        else:
            for m in self.last_matches:
                san_fn = RemediationEngine.build_sanitizer(m.flaw)
                rows = CounterfactualSimulator.simulate(
                    m.flaw, m.target_name, sanitizer_fn=san_fn
                )
                self.ledger_text.insert(
                    "end", f"[{m.flaw.flaw_id} on {m.target_name}]\n"
                )
                for r in rows:
                    self.ledger_text.insert(
                        "end",
                        f"  input={r['input']!r} -> BLOCK={r['block_outcome']} | "
                        f"SANITIZE={r['sanitize_outcome']} | AUDIT={r['audit_outcome']}\n",
                    )
                self.ledger_text.insert("end", "\n")

        self.ledger_text.insert("end", "=== Rule Diagnostics (Overlap & Bypass Vectors) ===\n")
        any_diag = False
        for tname in ("resolve_bench_path", "parse_bench_command_tokens"):
            diags = RuleDiagnostics.analyze_target(tname, registry.rules_for(tname))
            for d in diags:
                any_diag = True
                self.ledger_text.insert("end", f"  [{tname}] {d}\n")
        if not any_diag:
            self.ledger_text.insert(
                "end", "No rule overlap or bypass warnings detected.\n"
            )

    def verify_ledger_chain(self) -> None:
        ok, msg = rollback_ledger.verify_integrity()
        self._log(f"Ledger verification: {msg}")
        self.run_counterfactual_and_diagnostics()
        messagebox.showinfo("Ledger Integrity", msg)

    def rollback_to_checkpoint(self) -> None:
        cp_id = self.cp_var.get().strip().upper()
        cp = rollback_ledger.get_by_id(cp_id)
        if not cp:
            messagebox.showwarning("Not found", f"Checkpoint '{cp_id}' not found.")
            return
        registry.restore_rule_specs(cp.rule_specs)
        weight_store.restore_snapshot(cp.weights_snapshot)
        rollback_ledger.record_checkpoint(
            label=f"Rollback to {cp.checkpoint_id}",
            weights_snapshot=weight_store.snapshot(),
            rule_specs=registry.export_rule_specs(),
        )
        self.refresh_reasoning_view()
        self.run_counterfactual_and_diagnostics()
        self._log(
            f"Rolled back rules and learned weights to {cp.checkpoint_id} ({cp.label})."
        )
        messagebox.showinfo(
            "Rollback complete",
            f"Restored state from {cp.checkpoint_id} and appended rollback entry.",
        )

    def refresh_reasoning_view(self) -> None:
        self.reasoning_text.delete("1.0", "end")
        weights_snap = weight_store.snapshot()
        self.reasoning_text.insert("end", "=== Learned Weights ===\n")
        if not weights_snap:
            self.reasoning_text.insert("end", "No learned weights recorded yet.\n\n")
        else:
            for key, info in weights_snap.items():
                self.reasoning_text.insert(
                    "end",
                    f"  {key}: weight={info.get('weight', 1.0):.4f} "
                    f"(samples={info.get('samples', 0)}) — {info.get('last_reason', '')}\n",
                )
            self.reasoning_text.insert("end", "\n")

        self.reasoning_text.insert("end", "=== Chain-of-Thought Reasoning Traces ===\n\n")
        if not self.traces:
            self.reasoning_text.insert("end", "No reasoning traces recorded yet.\n")
        else:
            for trace in reversed(self.traces[-25:]):
                self.reasoning_text.insert("end", trace.format_text() + "\n\n")

    def reset_weights_view(self) -> None:
        weight_store.reset()
        self.refresh_reasoning_view()
        self._log("Reset all persisted learning weights.")

    def refresh_events_view(self) -> None:
        self.events_text.delete("1.0", "end")
        events = registry.events
        if not events:
            self.events_text.insert("end", "No guard events recorded yet.\n")
            return
        for ev in events:
            self.events_text.insert(
                "end",
                f"[{ev.timestamp}] target={ev.target_name} rule={ev.guard_name} "
                f"action={ev.action.value.upper()} blocked={ev.blocked} "
                f"args={ev.args_preview}\n",
            )

    def clear_events_view(self) -> None:
        registry.clear_events()
        self.refresh_events_view()
        self._log("Cleared recorded guard events.")

    def export_events_json(self) -> None:
        events = registry.events
        if not events:
            messagebox.showinfo("No events", "No guard events to export.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="guard_events.json",
        )
        if not file_path:
            return
        serializable = [
            {
                "timestamp": ev.timestamp,
                "target_name": ev.target_name,
                "guard_name": ev.guard_name,
                "flaw_id": ev.flaw_id,
                "action": ev.action.value,
                "blocked": ev.blocked,
                "reason": ev.reason,
                "args_preview": ev.args_preview,
            }
            for ev in events
        ]
        atomic_write_json(Path(file_path), serializable)
        self._log(f"Exported {len(serializable)} guard event(s) to {file_path}.")

    def open_cache_folder(self) -> None:
        self.client.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(self.client.cache_dir))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(self.client.cache_dir)])
            else:
                subprocess.Popen(["xdg-open", str(self.client.cache_dir)])
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc))

    def _on_close(self) -> None:
        self._stop_auto.set()
        self.destroy()


def main() -> None:
    app = CVEBenchApp()
    app.mainloop()


if __name__ == "__main__":
    main()