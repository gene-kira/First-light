"""
Live CVE Fetcher + Flaw Checker — Live Test Bench Edition
Python 3.9+ | Standard library only

Notes:
- NVD records describe vulnerabilities; validate applicability against actual
  packages, versions, and configurations on your test bench.
- Guard rules (BLOCK / SANITIZE / AUDIT) apply to functions wrapped with
  GuardRegistry.protect().
- Counterfactual simulations, mutation-resilience lattices, boundary & grammar
  invariant verifiers, epistemic equivalence-class blind-spot cartography,
  minimal counterexample witness & repair synthesis, counterfactual blast-radius
  & regret minimization, bypass/overlap diagnostics, hash-chained snapshots,
  learning weights, batch outcomes, evolution memory, causal drift analysis,
  multi-horizon predictive forecasting, and reasoning traces are local
  deterministic engineering tools.
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
from urllib.parse import urlencode, unquote
from urllib.request import Request, urlopen
import copy
import hashlib
import json
import math
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "Live CVE Fetcher + Flaw Checker — Test Bench"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_DIR = Path(__file__).resolve().parent / "cve_cache"
DEFAULT_SANDBOX_DIR = Path(__file__).resolve().parent / "test_bench_sandbox"
DEFAULT_WEIGHTS_PATH = Path(__file__).resolve().parent / "bench_weights.json"
DEFAULT_LEDGER_PATH = Path(__file__).resolve().parent / "bench_ledger.json"
DEFAULT_EVOLUTION_PATH = (
    Path(__file__).resolve().parent / "vulnerability_evolution_memory.json"
)
DEFAULT_CAUSAL_PATH = (
    Path(__file__).resolve().parent / "causal_drift_ledger.json"
)
DEFAULT_MUTATION_PATH = (
    Path(__file__).resolve().parent / "mutation_lattice_memory.json"
)
DEFAULT_BOUNDARY_PATH = (
    Path(__file__).resolve().parent / "boundary_grammar_memory.json"
)
DEFAULT_EPISTEMIC_PATH = (
    Path(__file__).resolve().parent / "epistemic_cartography_memory.json"
)
DEFAULT_WITNESS_PATH = (
    Path(__file__).resolve().parent / "invariant_witness_memory.json"
)
DEFAULT_BLAST_PATH = (
    Path(__file__).resolve().parent / "blast_radius_memory.json"
)

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

    def add(
        self, stage: str, detail: str, weight_delta: Optional[float] = None
    ) -> None:
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
    Produces context-aware, multi-pass fixes for matched flaw patterns and
    supports deeper canonicalization/neutralization of traversal and command
    injection payloads, including multi-pass encoded, Unicode-escaped, null-byte,
    and nested substitution variants.
    """

    @staticmethod
    def _decode_iterative(text: str, max_passes: int = 6) -> str:
        cur = text
        for _ in range(max_passes):
            decoded = unquote(cur)
            decoded = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda m: chr(int(m.group(1), 16)),
                decoded,
            )
            if decoded == cur:
                break
            cur = decoded
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cur)

    @staticmethod
    def _strip_nested_substitutions(text: str, max_passes: int = 6) -> str:
        cur = text
        for _ in range(max_passes):
            nxt = re.sub(r"\$\([^()]*\)|`[^`]*`", " ", cur)
            if nxt == cur:
                break
            cur = nxt
        return cur

    @staticmethod
    def build_sanitizer(flaw: FlawRecord) -> Callable[[str], str]:
        pattern = flaw.block_pattern
        probe = flaw.probe_name
        desc_lower = (flaw.description or "").lower()

        def _sanitize(raw: str) -> str:
            if not isinstance(raw, str):
                return raw
            text = RemediationEngine._decode_iterative(raw)
            if probe == "check_path_resolution" or "traversal" in desc_lower:
                slashed = re.sub(r"[/\\]+", "/", text).strip()
                normalized = posixpath.normpath(slashed)
                parts = [
                    p
                    for p in normalized.split("/")
                    if p and p not in (".", "..") and not p.startswith("..")
                ]
                text = "/".join(parts)
            if (
                probe == "check_command_tokenization"
                or "command" in desc_lower
                or "injection" in desc_lower
            ):
                text = RemediationEngine._strip_nested_substitutions(text)
                text = re.sub(r"[;&|`$<>!\\r\\n]+", " ", text)
                text = re.sub(r"\s+", " ", text).strip()
            if pattern:
                try:
                    cleaned_pat = re.sub(
                        pattern, "", text, flags=re.IGNORECASE
                    ).strip()
                    if cleaned_pat:
                        text = cleaned_pat
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
                compiled = (
                    re.compile(pattern, re.IGNORECASE) if pattern else None
                )
            except re.error:
                compiled = None

            def _make_pred(
                rx: Optional[re.Pattern[str]],
            ) -> Callable[..., bool]:
                def _pred(*args: Any, **kwargs: Any) -> bool:
                    if rx is None:
                        return False
                    return any(
                        bool(rx.search(s))
                        for s in _iter_string_inputs(args, kwargs)
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
                return re.sub(
                    rule.block_pattern, "", value, flags=re.IGNORECASE
                )
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
                    matched = bool(
                        rule.predicate(*active_args, **active_kwargs)
                    )
                except Exception as exc:
                    if rule.action == GuardAction.BLOCK:
                        event = self._record(
                            rule, True, active_args, active_kwargs
                        )
                        raise GuardBlockedError(
                            f"Guard predicate failed; call blocked: {exc}",
                            event,
                        ) from exc
                    continue

                if matched:
                    if rule.action == GuardAction.BLOCK:
                        event = self._record(
                            rule, True, active_args, active_kwargs
                        )
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
                self._checkpoints[-1].entry_hash
                if self._checkpoints
                else "GENESIS"
            )
            ts = datetime.now(timezone.utc).isoformat()
            cp_id = f"CP-{idx + 1:04d}"
            w_copy = copy.deepcopy(weights_snapshot)
            r_copy = copy.deepcopy(rule_specs)
            entry_hash = self._compute_hash(
                idx, ts, label, prev_hash, w_copy, r_copy
            )
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
                    re.sub(
                        flaw.block_pattern, "", sample, flags=re.IGNORECASE
                    ).strip()
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
                    elif (
                        a.priority > b.priority
                        and a.action == GuardAction.BLOCK
                    ):
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


class MutationLatticeEngine:
    """
    Counterfactual Mutation & Bypass-Resilience Lattice.
    Synthesizes deterministic attack/encoding mutations and benign control inputs,
    evaluates rule detection/sanitization resilience across variants, flags blind
    spots, and persists historical resilience profiles.
    """

    THREAT_MUTATIONS: dict[str, list[str]] = {
        "resolve_bench_path": [
            "../outside-bench/target.conf",
            "..\\..\\windows\\win.ini",
            "....//....//etc/passwd",
            "..%2f..%2fetc/passwd",
            "%2e%2e/%2e%2e/secret.key",
            "reports/../../etc/shadow\x00.json",
            "/etc/passwd",
        ],
        "parse_bench_command_tokens": [
            "status --verbose; echo check_token",
            "status $(whoami) | cat",
            "status `id`",
            "status\nrm -rf /tmp/x",
            "status &background_job",
            "status $(echo $(uname -a))",
            "status > /tmp/out.txt",
        ],
    }

    BENIGN_MUTATIONS: dict[str, list[str]] = {
        "resolve_bench_path": [
            "reports/2026/summary.json",
            "logs/daily/app-01.log",
            "configs/bench_manifest.json",
        ],
        "parse_bench_command_tokens": [
            "status --verbose",
            "healthcheck --json --timeout=5",
            "version --short",
        ],
    }

    MAX_RECORDS = 1000

    def __init__(self, storage_path: Path = DEFAULT_MUTATION_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._profiles: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("profiles"), dict):
                self._profiles = raw["profiles"]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                self.storage_path,
                {
                    "profiles": dict(
                        list(self._profiles.items())[-self.MAX_RECORDS :]
                    )
                },
            )
        except OSError:
            pass

    @classmethod
    def evaluate_lattice(
        cls,
        flaw: FlawRecord,
        target_name: str,
        rules: list[GuardRule],
        persist: bool = True,
    ) -> dict[str, Any]:
        threats = cls.THREAT_MUTATIONS.get(
            target_name,
            ["../outside-bench/target.conf", "cmd; token", "$(id)"],
        )
        benign = cls.BENIGN_MUTATIONS.get(
            target_name, ["reports/summary.json", "status --verbose"]
        )

        enabled = [r for r in rules if r.enabled]
        compiled_rules: list[tuple[GuardRule, Optional[re.Pattern[str]]]] = []
        for r in enabled:
            try:
                rx = (
                    re.compile(r.block_pattern, re.IGNORECASE)
                    if r.block_pattern
                    else None
                )
            except re.error:
                rx = None
            compiled_rules.append((r, rx))

        caught_threats: list[str] = []
        missed_threats: list[str] = []

        for payload in threats:
            decoded_payload = RemediationEngine._decode_iterative(payload)
            hit_any = False
            for r, rx in compiled_rules:
                if rx and (rx.search(payload) or rx.search(decoded_payload)):
                    hit_any = True
                    break
            if hit_any:
                caught_threats.append(payload)
            else:
                missed_threats.append(payload)

        preserved_benign = 0
        for b_payload in benign:
            over_blocked = False
            for r, rx in compiled_rules:
                if r.action == GuardAction.BLOCK and rx and rx.search(b_payload):
                    over_blocked = True
                    break
            if not over_blocked:
                preserved_benign += 1

        resilience = round(len(caught_threats) / max(1, len(threats)), 3)
        benign_preservation = round(
            preserved_benign / max(1, len(benign)), 3
        )
        lattice_score = round(
            (resilience * 0.75 + benign_preservation * 0.25) * 100.0, 1
        )

        result = {
            "flaw_id": flaw.flaw_id,
            "target_name": target_name,
            "threats_tested": len(threats),
            "threats_caught": len(caught_threats),
            "missed_threats": missed_threats,
            "resilience_ratio": resilience,
            "benign_preservation": benign_preservation,
            "lattice_score": lattice_score,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        if persist:
            instance = mutation_lattice
            k = cls._key(flaw.flaw_id, target_name)
            with instance._lock:
                prev = instance._profiles.get(k) or {}
                runs = int(prev.get("runs", 0)) + 1
                result["runs"] = runs
                instance._profiles[k] = result
                instance._save_locked()
        return result

    def get_resilience(self, flaw_id: str, target_name: str) -> float:
        k = self._key(flaw_id, target_name)
        with self._lock:
            prof = self._profiles.get(k)
            if not isinstance(prof, dict):
                return 0.5
            try:
                return max(
                    0.0, min(1.0, float(prof.get("resilience_ratio", 0.5)))
                )
            except (TypeError, ValueError):
                return 0.5

    def report(self) -> str:
        with self._lock:
            profiles = [copy.deepcopy(v) for v in self._profiles.values()]
        lines = [
            "=== COUNTERFACTUAL MUTATION & BYPASS-RESILIENCE LATTICE ==="
        ]
        if not profiles:
            lines.append(
                "No mutation lattice evaluations recorded yet. Run checks, install guards, or refresh."
            )
            return "\n".join(lines)
        for p in sorted(
            profiles, key=lambda x: x.get("lattice_score", 0.0)
        ):
            missed = p.get("missed_threats") or []
            blind_note = (
                f" | BLIND_SPOTS={missed[:4]}"
                if missed
                else " | ZERO_BLIND_SPOTS"
            )
            lines.append(
                f"  {p.get('flaw_id')} -> {p.get('target_name')}: "
                f"score={p.get('lattice_score', 0.0)}/100 "
                f"(resilience={float(p.get('resilience_ratio', 0.0)):.0%}, "
                f"benign_ok={float(p.get('benign_preservation', 0.0)):.0%}, "
                f"caught={p.get('threats_caught', 0)}/{p.get('threats_tested', 0)}){blind_note}"
            )
        return "\n".join(lines)


class BoundaryGrammarEngine:
    """
    Invariant-Preserving Symbolic Boundary & Grammar Fuzz-Verifier.
    Generates grammar-derived boundary inputs and verifies both threat
    neutralization and benign input invariance across rules and sanitizers.
    """

    BOUNDARY_VECTORS: dict[str, list[tuple[str, bool]]] = {
        "resolve_bench_path": [
            ("../outside-bench/target.conf", True),
            ("..\\..\\windows\\win.ini", True),
            ("%252e%252e%252fetc/passwd", True),
            ("....//....//etc/passwd", True),
            ("/etc/passwd", True),
            ("reports/2026/summary.json", False),
            ("logs/daily/app-01.log", False),
        ],
        "parse_bench_command_tokens": [
            ("status --verbose; echo check_token", True),
            ("status $(whoami) | cat", True),
            ("status `id`", True),
            ("status\nrm -rf /tmp/x", True),
            ("status $(echo $(id))", True),
            ("status --verbose", False),
            ("version --short", False),
        ],
    }

    def __init__(self, storage_path: Path = DEFAULT_BOUNDARY_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._records: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("records"), dict):
                self._records = raw["records"]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.storage_path, {"records": self._records})
        except OSError:
            pass

    @classmethod
    def verify_boundaries(
        cls,
        flaw: FlawRecord,
        target_name: str,
        rules: list[GuardRule],
        persist: bool = True,
    ) -> dict[str, Any]:
        vectors = cls.BOUNDARY_VECTORS.get(
            target_name,
            [("../escape", True), ("cmd; x", True), ("ok_input", False)],
        )
        enabled = [r for r in rules if r.enabled]
        sanitizer_fn = RemediationEngine.build_sanitizer(flaw)

        threat_total = 0
        threat_neutralized = 0
        benign_total = 0
        benign_preserved = 0
        violations: list[str] = []

        for sample, is_threat in vectors:
            if is_threat:
                threat_total += 1
                decoded = RemediationEngine._decode_iterative(sample)
                matched = False
                for r in enabled:
                    if not r.block_pattern:
                        continue
                    try:
                        rx = re.compile(r.block_pattern, re.IGNORECASE)
                        if rx.search(sample) or rx.search(decoded):
                            matched = True
                            break
                    except re.error:
                        continue
                san_out = sanitizer_fn(sample)
                neutralized = matched or (san_out != sample)
                if neutralized:
                    threat_neutralized += 1
                else:
                    violations.append(
                        f"Unneutralized boundary threat: {sample!r}"
                    )
            else:
                benign_total += 1
                blocked_on_benign = False
                for r in enabled:
                    if r.action == GuardAction.BLOCK and r.block_pattern:
                        try:
                            if re.search(
                                r.block_pattern, sample, re.IGNORECASE
                            ):
                                blocked_on_benign = True
                                break
                        except re.error:
                            pass
                if not blocked_on_benign:
                    benign_preserved += 1
                else:
                    violations.append(
                        f"False-positive block on benign: {sample!r}"
                    )

        threat_rate = round(threat_neutralized / max(1, threat_total), 3)
        benign_rate = round(benign_preserved / max(1, benign_total), 3)
        boundary_score = round(
            (threat_rate * 0.70 + benign_rate * 0.30) * 100.0, 1
        )

        entry = {
            "flaw_id": flaw.flaw_id,
            "target_name": target_name,
            "threat_neutralized": threat_neutralized,
            "threat_total": threat_total,
            "benign_preserved": benign_preserved,
            "benign_total": benign_total,
            "threat_rate": threat_rate,
            "benign_rate": benign_rate,
            "boundary_score": boundary_score,
            "violations": violations,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        if persist:
            k = cls._key(flaw.flaw_id, target_name)
            with boundary_engine._lock:
                boundary_engine._records[k] = entry
                boundary_engine._save_locked()
        return entry

    def get_boundary_score(self, flaw_id: str, target_name: str) -> float:
        k = self._key(flaw_id, target_name)
        with self._lock:
            rec = self._records.get(k)
            if not isinstance(rec, dict):
                return 55.0
            try:
                return max(
                    0.0, min(100.0, float(rec.get("boundary_score", 55.0)))
                )
            except (TypeError, ValueError):
                return 55.0

    def report(self) -> str:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._records.values()]
        lines = [
            "=== INVARIANT-PRESERVING BOUNDARY & GRAMMAR VERIFIER ==="
        ]
        if not items:
            lines.append(
                "No boundary grammar evaluations recorded yet. Run a boundary scan or bench check."
            )
            return "\n".join(lines)
        for it in sorted(
            items, key=lambda x: x.get("boundary_score", 0.0)
        ):
            viols = it.get("violations") or []
            v_str = f" | VIOLATIONS={viols}" if viols else " | INVARIANTS_HOLD"
            lines.append(
                f"  {it.get('flaw_id')} -> {it.get('target_name')}: "
                f"boundary_score={it.get('boundary_score', 0.0)}/100 "
                f"(threats={it.get('threat_neutralized', 0)}/{it.get('threat_total', 0)}, "
                f"benign_preserved={it.get('benign_preserved', 0)}/{it.get('benign_total', 0)}){v_str}"
            )
        return "\n".join(lines)


class EpistemicCartographer:
    """
    Epistemic Equivalence-Class & Blind-Spot Cartographer.
    Partitions attack & benign payloads into semantic equivalence classes,
    computes normalized Shannon epistemic uncertainty (blind-spot entropy) over
    uncovered threat classes, and ranks highest-information-gain hardening targets.
    """

    EQUIVALENCE_CLASSES: dict[str, list[tuple[str, str, bool]]] = {
        "resolve_bench_path": [
            ("DOT_DOT_TRAVERSAL", "../outside-bench/target.conf", True),
            ("BACKSLASH_TRAVERSAL", "..\\..\\windows\\win.ini", True),
            ("DOUBLE_ENCODED_TRAVERSAL", "%252e%252e%252fetc/passwd", True),
            ("OVERLONG_SLASH_TRAVERSAL", "....//....//etc/passwd", True),
            ("ROOT_ANCHOR_ESCAPE", "/etc/passwd", True),
            ("BENIGN_CANONICAL_PATH", "reports/2026/summary.json", False),
        ],
        "parse_bench_command_tokens": [
            ("COMMAND_CHAIN_SEPARATOR", "status --verbose; echo check_token", True),
            ("SUBSHELL_EXPANSION", "status $(whoami) | cat", True),
            ("BACKTICK_SUBSTITUTION", "status `id`", True),
            ("NEWLINE_CONTROL_INJECTION", "status\nrm -rf /tmp/x", True),
            ("NESTED_SUBSHELL", "status $(echo $(id))", True),
            ("BENIGN_FLAGS_ARGS", "status --verbose --timeout=5", False),
        ],
    }

    def __init__(self, storage_path: Path = DEFAULT_EPISTEMIC_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._maps: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("maps"), dict):
                self._maps = raw["maps"]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.storage_path, {"maps": self._maps})
        except OSError:
            pass

    @classmethod
    def map_epistemic_space(
        cls,
        flaw: FlawRecord,
        target_name: str,
        rules: list[GuardRule],
        learned_weight: float = 1.0,
        persist: bool = True,
    ) -> dict[str, Any]:
        classes = cls.EQUIVALENCE_CLASSES.get(
            target_name,
            [
                ("GENERIC_ESCAPE", "../escape", True),
                ("GENERIC_CHAIN", "cmd; x", True),
                ("BENIGN_INPUT", "ok_input", False),
            ],
        )
        enabled = [r for r in rules if r.enabled]
        sanitizer_fn = RemediationEngine.build_sanitizer(flaw)

        covered_classes: list[str] = []
        blind_classes: list[str] = []
        info_gain_ranking: list[dict[str, Any]] = []

        threat_classes = [c for c in classes if c[2]]
        for eq_class, sample, _is_threat in threat_classes:
            decoded = RemediationEngine._decode_iterative(sample)
            matched = False
            for r in enabled:
                if not r.block_pattern:
                    continue
                try:
                    rx = re.compile(r.block_pattern, re.IGNORECASE)
                    if rx.search(sample) or rx.search(decoded):
                        matched = True
                        break
                except re.error:
                    continue
            san_out = sanitizer_fn(sample)
            neutralized = matched or (san_out != sample)
            if neutralized:
                covered_classes.append(eq_class)
            else:
                blind_classes.append(eq_class)
                eig = round(
                    min(
                        1.0,
                        (0.35 + (1.0 / max(1, len(threat_classes))))
                        * max(0.75, min(1.35, learned_weight)),
                    ),
                    3,
                )
                info_gain_ranking.append(
                    {
                        "equivalence_class": eq_class,
                        "probe_sample": sample,
                        "expected_info_gain": eig,
                    }
                )

        info_gain_ranking.sort(
            key=lambda x: x["expected_info_gain"], reverse=True
        )

        total_threats = max(1, len(threat_classes))
        p_uncovered = len(blind_classes) / total_threats
        if p_uncovered <= 0.0 or p_uncovered >= 1.0:
            entropy_norm = 0.0
        else:
            h = -(
                p_uncovered * math.log2(p_uncovered)
                + (1.0 - p_uncovered) * math.log2(1.0 - p_uncovered)
            )
            entropy_norm = round(h, 3)

        epistemic_certainty = round(
            max(
                0.0,
                min(
                    100.0,
                    ((len(covered_classes) / total_threats) * 100.0)
                    * (1.0 - 0.25 * entropy_norm),
                ),
            ),
            1,
        )

        entry = {
            "flaw_id": flaw.flaw_id,
            "target_name": target_name,
            "covered_classes": covered_classes,
            "blind_classes": blind_classes,
            "epistemic_entropy": entropy_norm,
            "epistemic_certainty": epistemic_certainty,
            "info_gain_ranking": info_gain_ranking,
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }

        if persist:
            k = cls._key(flaw.flaw_id, target_name)
            with epistemic_cartographer._lock:
                epistemic_cartographer._maps[k] = entry
                epistemic_cartographer._save_locked()
        return entry

    def get_certainty(self, flaw_id: str, target_name: str) -> float:
        k = self._key(flaw_id, target_name)
        with self._lock:
            rec = self._maps.get(k)
            if not isinstance(rec, dict):
                return 50.0
            try:
                return max(
                    0.0, min(100.0, float(rec.get("epistemic_certainty", 50.0)))
                )
            except (TypeError, ValueError):
                return 50.0

    def report(self) -> str:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._maps.values()]
        lines = [
            "=== EPISTEMIC EQUIVALENCE-CLASS & BLIND-SPOT CARTOGRAPHER ==="
        ]
        if not items:
            lines.append(
                "No epistemic maps recorded yet. Run an epistemic scan or bench check."
            )
            return "\n".join(lines)
        for it in sorted(
            items, key=lambda x: x.get("epistemic_certainty", 0.0)
        ):
            blind = it.get("blind_classes") or []
            covered = it.get("covered_classes") or []
            lines.append(
                f"  {it.get('flaw_id')} -> {it.get('target_name')}: "
                f"certainty={it.get('epistemic_certainty', 0.0)}/100 | "
                f"entropy={it.get('epistemic_entropy', 0.0)} | "
                f"covered={len(covered)} | blind_classes={blind or 'NONE'}"
            )
            for item in (it.get("info_gain_ranking") or [])[:3]:
                lines.append(
                    f"     -> EIG={item.get('expected_info_gain')} for class '{item.get('equivalence_class')}' "
                    f"(probe={item.get('probe_sample')!r})"
                )
        return "\n".join(lines)


class InvariantWitnessEngine:
    """
    Minimal Counterexample Witness & Structural Repair Synthesizer.
    Extracts the shortest/minimal counterexample witness that evades or stresses
    active rule patterns on a target, computes a witness evasion risk score, and
    synthesizes a concrete minimal structural repair.
    """

    WITNESS_POOL: dict[str, list[tuple[str, str]]] = {
        "resolve_bench_path": [
            (
                "../x",
                "Canonicalize decoded path segments and reject '..' or leading '/'.",
            ),
            (
                "..\\x",
                "Normalize backslashes to '/' and strip parent-directory segments.",
            ),
            (
                "%2e%2e/x",
                "Apply iterative URL unquoting before path traversal checks.",
            ),
            (
                "....//x",
                "Collapse repeated slash/dot runs before checking containment.",
            ),
        ],
        "parse_bench_command_tokens": [
            (
                "ok;x",
                "Reject or strip command chaining delimiters (;, &, |, newline) before tokenizing.",
            ),
            (
                "ok `x`",
                "Strip backtick command substitution and nested $(...) expansions.",
            ),
            (
                "ok $(x)",
                "Remove subshell expansion constructs and control characters.",
            ),
            (
                "ok\nx",
                "Strip embedded CR/LF control bytes prior to argument parsing.",
            ),
        ],
    }

    def __init__(self, storage_path: Path = DEFAULT_WITNESS_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._witnesses: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("witnesses"), dict):
                self._witnesses = raw["witnesses"]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                self.storage_path, {"witnesses": self._witnesses}
            )
        except OSError:
            pass

    @classmethod
    def synthesize_witness(
        cls,
        flaw: FlawRecord,
        target_name: str,
        rules: list[GuardRule],
        learned_weight: float = 1.0,
        persist: bool = True,
    ) -> dict[str, Any]:
        pool = cls.WITNESS_POOL.get(
            target_name,
            [
                (
                    "../x",
                    "Canonicalize path segments and reject escape prefixes.",
                ),
                (
                    "ok;x",
                    "Strip command chaining operators before tokenization.",
                ),
            ],
        )
        enabled = [r for r in rules if r.enabled]
        compiled: list[Optional[re.Pattern[str]]] = []
        for r in enabled:
            if not r.block_pattern:
                compiled.append(None)
                continue
            try:
                compiled.append(re.compile(r.block_pattern, re.IGNORECASE))
            except re.error:
                compiled.append(None)

        sanitizer_fn = RemediationEngine.build_sanitizer(flaw)
        evading: list[tuple[str, str]] = []
        for witness_input, repair_hint in pool:
            decoded = RemediationEngine._decode_iterative(witness_input)
            caught_by_regex = any(
                rx is not None and (rx.search(witness_input) or rx.search(decoded))
                for rx in compiled
            )
            neutralized_by_san = sanitizer_fn(witness_input) != witness_input
            if not caught_by_regex and not neutralized_by_san:
                evading.append((witness_input, repair_hint))

        if evading:
            evading.sort(key=lambda pair: (len(pair[0]), pair[0]))
            minimal_witness, repair_plan = evading[0]
            evasion_pressure = round(
                min(
                    100.0,
                    (len(evading) / max(1, len(pool)))
                    * 85.0
                    * max(0.75, min(1.30, learned_weight)),
                ),
                1,
            )
            status = "COUNTEREXAMPLE_FOUND"
        else:
            minimal_witness = "<NONE: all minimal witnesses neutralized>"
            repair_plan = (
                "Current rule pattern and structural sanitizer neutralize all minimal probes; "
                "maintain periodic re-verification."
            )
            evasion_pressure = 0.0
            status = "WITNESS_FREE"

        entry = {
            "flaw_id": flaw.flaw_id,
            "target_name": target_name,
            "status": status,
            "minimal_witness": minimal_witness,
            "evading_count": len(evading),
            "pool_size": len(pool),
            "evasion_pressure": evasion_pressure,
            "repair_plan": repair_plan,
            "synthesized_at": datetime.now(timezone.utc).isoformat(),
        }

        if persist:
            k = cls._key(flaw.flaw_id, target_name)
            with witness_engine._lock:
                witness_engine._witnesses[k] = entry
                witness_engine._save_locked()
        return entry

    def get_evasion_pressure(self, flaw_id: str, target_name: str) -> float:
        k = self._key(flaw_id, target_name)
        with self._lock:
            rec = self._witnesses.get(k)
            if not isinstance(rec, dict):
                return 25.0
            try:
                return max(
                    0.0, min(100.0, float(rec.get("evasion_pressure", 25.0)))
                )
            except (TypeError, ValueError):
                return 25.0

    def report(self) -> str:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._witnesses.values()]
        lines = [
            "=== MINIMAL COUNTEREXAMPLE WITNESS & STRUCTURAL REPAIR SYNTHESIZER ==="
        ]
        if not items:
            lines.append(
                "No counterexample witnesses synthesized yet. Run a witness scan or bench check."
            )
            return "\n".join(lines)
        for it in sorted(
            items, key=lambda x: x.get("evasion_pressure", 0.0), reverse=True
        ):
            lines.append(
                f"  {it.get('flaw_id')} -> {it.get('target_name')}: "
                f"status={it.get('status')} | pressure={it.get('evasion_pressure', 0.0)}/100 | "
                f"evading={it.get('evading_count', 0)}/{it.get('pool_size', 0)} | "
                f"witness={it.get('minimal_witness')!r}"
            )
            lines.append(f"     -> Structural Repair: {it.get('repair_plan')}")
        return "\n".join(lines)


class BlastRadiusRegretEngine:
    """
    Counterfactual Blast-Radius & Regret Minimizer.
    Evaluates each candidate guard mode (BLOCK, SANITIZE, AUDIT) against:
    - Blast radius (0..100): scope of benign disruption if a rule over-matches.
    - Expected regret (0..100): missed-exploit regret vs false-positive disruption regret.
    Picks the action with lowest expected regret within blast tolerance.
    """

    def __init__(self, storage_path: Path = DEFAULT_BLAST_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._records: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str) -> str:
        return f"{flaw_id.upper()}::{target_name}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("records"), dict):
                self._records = raw["records"]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.storage_path, {"records": self._records})
        except OSError:
            pass

    @classmethod
    def evaluate_regret(
        cls,
        flaw: FlawRecord,
        target_name: str,
        rules: list[GuardRule],
        learned_weight: float = 1.0,
        resilience_ratio: float = 0.5,
        witness_pressure: float = 25.0,
        persist: bool = True,
    ) -> dict[str, Any]:
        sev_risk = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.78,
            Severity.MEDIUM: 0.52,
            Severity.LOW: 0.28,
        }[flaw.severity]
        benign_samples = MutationLatticeEngine.BENIGN_MUTATIONS.get(
            target_name, ["reports/2026/summary.json", "status --verbose"]
        )
        enabled = [r for r in rules if r.enabled]
        overblock_hits = 0
        for sample in benign_samples:
            for r in enabled:
                if r.action == GuardAction.BLOCK and r.block_pattern:
                    try:
                        if re.search(r.block_pattern, sample, re.IGNORECASE):
                            overblock_hits += 1
                            break
                    except re.error:
                        pass
        overblock_rate = overblock_hits / max(1, len(benign_samples))
        w_factor = max(0.70, min(1.35, learned_weight))
        w_norm = max(0.0, min(1.0, witness_pressure / 100.0))
        evasion_gap = max(0.0, min(1.0, 1.0 - resilience_ratio))

        # Blast radius (0..100): higher when BLOCK is broad or benign over-blocking appears
        block_blast = round(
            min(100.0, (25.0 + overblock_rate * 55.0 + w_norm * 10.0) * w_factor),
            1,
        )
        sanitize_blast = round(
            min(100.0, (12.0 + overblock_rate * 25.0 + evasion_gap * 10.0)),
            1,
        )
        audit_blast = round(min(100.0, 5.0 + overblock_rate * 10.0), 1)

        # Expected regret (0..100): lower is better
        block_regret = round(
            min(
                100.0,
                overblock_rate * 55.0
                + (1.0 - sev_risk) * 20.0
                + evasion_gap * 12.0,
            ),
            1,
        )
        sanitize_regret = round(
            min(
                100.0,
                (1.0 - sev_risk) * 18.0
                + evasion_gap * 24.0
                + w_norm * 14.0
                + overblock_rate * 12.0,
            ),
            1,
        )
        audit_regret = round(
            min(
                100.0,
                sev_risk * 65.0 + w_norm * 20.0 + evasion_gap * 15.0,
            ),
            1,
        )

        regret_by_action = {
            GuardAction.BLOCK: block_regret,
            GuardAction.SANITIZE: sanitize_regret,
            GuardAction.AUDIT: audit_regret,
        }
        blast_by_action = {
            GuardAction.BLOCK: block_blast,
            GuardAction.SANITIZE: sanitize_blast,
            GuardAction.AUDIT: audit_blast,
        }

        if flaw.severity in (Severity.CRITICAL, Severity.HIGH) and block_blast <= 75.0:
            best_action = GuardAction.BLOCK
        else:
            best_action = min(
                (GuardAction.BLOCK, GuardAction.SANITIZE, GuardAction.AUDIT),
                key=lambda a: (regret_by_action[a], blast_by_action[a]),
            )

        entry = {
            "flaw_id": flaw.flaw_id,
            "target_name": target_name,
            "best_action": best_action.value.upper(),
            "blast_radius": {
                "block": block_blast,
                "sanitize": sanitize_blast,
                "audit": audit_blast,
            },
            "expected_regret": {
                "block": block_regret,
                "sanitize": sanitize_regret,
                "audit": audit_regret,
            },
            "min_regret": regret_by_action[best_action],
            "selected_blast": blast_by_action[best_action],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        if persist:
            k = cls._key(flaw.flaw_id, target_name)
            with blast_regret_engine._lock:
                blast_regret_engine._records[k] = entry
                blast_regret_engine._save_locked()
        return entry

    def get_entry(self, flaw_id: str, target_name: str) -> Optional[dict[str, Any]]:
        k = self._key(flaw_id, target_name)
        with self._lock:
            rec = self._records.get(k)
            return copy.deepcopy(rec) if isinstance(rec, dict) else None

    def report(self) -> str:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._records.values()]
        lines = [
            "=== COUNTERFACTUAL BLAST-RADIUS & REGRET MINIMIZER ==="
        ]
        if not items:
            lines.append(
                "No blast-radius / regret evaluations recorded yet. Run bench checks or install guards."
            )
            return "\n".join(lines)
        for it in sorted(
            items, key=lambda x: x.get("min_regret", 100.0)
        ):
            br = it.get("blast_radius") or {}
            er = it.get("expected_regret") or {}
            lines.append(
                f"  {it.get('flaw_id')} -> {it.get('target_name')}: "
                f"best={it.get('best_action')} | min_regret={it.get('min_regret', 0.0)}/100 | "
                f"selected_blast={it.get('selected_blast', 0.0)}/100"
            )
            lines.append(
                f"     Blast[B/S/A]={br.get('block')}/{br.get('sanitize')}/{br.get('audit')} | "
                f"Regret[B/S/A]={er.get('block')}/{er.get('sanitize')}/{er.get('audit')}"
            )
        return "\n".join(lines)


class CausalDriftEngine:
    """
    Causal Counterfactual Drift & Guard-Effect Ledger.
    Tracks causal deltas between pre-guard probe outcomes, counterfactual expectations,
    and post-guard verification behavior to detect invariant drift and estimate
    true intervention effectiveness.
    """

    MAX_RECORDS = 2000

    def __init__(self, storage_path: Path = DEFAULT_CAUSAL_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._log: list[dict[str, Any]] = []
        self._load()

    @staticmethod
    def _key(flaw_id: str, target_name: str, action: str) -> str:
        return f"{flaw_id.upper()}::{target_name}::{action.upper()}"

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                if isinstance(raw.get("entries"), dict):
                    self._entries = raw["entries"]
                if isinstance(raw.get("log"), list):
                    self._log = raw["log"][-self.MAX_RECORDS :]
        except (OSError, json.JSONDecodeError):
            pass

    def _save_locked(self) -> None:
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                self.storage_path,
                {
                    "entries": self._entries,
                    "log": self._log[-self.MAX_RECORDS :],
                },
            )
        except OSError:
            pass

    def record_intervention(
        self,
        flaw_id: str,
        target_name: str,
        action: str,
        pre_matched: bool,
        counterfactual_hit_rate: float,
        post_verified_intercepted: Optional[bool] = None,
        note: str = "",
    ) -> dict[str, Any]:
        k = self._key(flaw_id, target_name, action)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            item = self._entries.setdefault(
                k,
                {
                    "flaw_id": flaw_id.upper(),
                    "target_name": target_name,
                    "action": action.upper(),
                    "interventions": 0,
                    "verified_runs": 0,
                    "confirmed_effects": 0,
                    "drift_events": 0,
                    "last_drift_score": 0.0,
                    "causal_effect_score": 0.5,
                    "updated_at": now,
                    "last_note": "",
                },
            )
            item["interventions"] = int(item.get("interventions", 0)) + 1
            item["updated_at"] = now

            drift_score = 0.0
            if post_verified_intercepted is not None:
                item["verified_runs"] = int(item.get("verified_runs", 0)) + 1
                expected_hit = counterfactual_hit_rate > 0.0 or pre_matched
                if action.upper() == "BLOCK":
                    if post_verified_intercepted and expected_hit:
                        item["confirmed_effects"] = (
                            int(item.get("confirmed_effects", 0)) + 1
                        )
                        drift_score = 0.0
                    elif not post_verified_intercepted and expected_hit:
                        item["drift_events"] = (
                            int(item.get("drift_events", 0)) + 1
                        )
                        drift_score = 0.75
                elif action.upper() == "SANITIZE":
                    if post_verified_intercepted or not pre_matched:
                        item["confirmed_effects"] = (
                            int(item.get("confirmed_effects", 0)) + 1
                        )
                        drift_score = 0.10
                    else:
                        item["drift_events"] = (
                            int(item.get("drift_events", 0)) + 1
                        )
                        drift_score = 0.55
                else:
                    drift_score = 0.15 if pre_matched else 0.0

            item["last_drift_score"] = round(drift_score, 2)
            v_runs = max(1, int(item.get("verified_runs", 0)))
            c_eff = int(item.get("confirmed_effects", 0))
            d_ev = int(item.get("drift_events", 0))
            raw_eff = (c_eff + 1.0) / (v_runs + 2.0) - (d_ev * 0.15)
            item["causal_effect_score"] = round(
                max(0.05, min(0.99, raw_eff)), 3
            )
            if note:
                item["last_note"] = str(note)[:300]

            self._log.append(
                {
                    "timestamp": now,
                    "key": k,
                    "pre_matched": pre_matched,
                    "counterfactual_hit_rate": round(
                        counterfactual_hit_rate, 2
                    ),
                    "post_verified_intercepted": post_verified_intercepted,
                    "drift_score": item["last_drift_score"],
                    "causal_effect_score": item["causal_effect_score"],
                    "note": str(note)[:200],
                }
            )
            self._save_locked()
            return copy.deepcopy(item)

    def drift_alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._entries.values()]
        alerts: list[dict[str, Any]] = []
        for it in items:
            if (
                int(it.get("drift_events", 0)) > 0
                or float(it.get("last_drift_score", 0.0)) >= 0.50
            ):
                alerts.append(
                    {
                        "key": f"{it['flaw_id']}::{it['target_name']}::{it['action']}",
                        "drift_score": it.get("last_drift_score", 0.0),
                        "drift_events": it.get("drift_events", 0),
                        "causal_effect_score": it.get(
                            "causal_effect_score", 0.5
                        ),
                        "message": (
                            f"[DRIFT delta={it.get('last_drift_score', 0.0):.2f}] "
                            f"{it['flaw_id']} on {it['target_name']} ({it['action']}): "
                            f"drift_events={it.get('drift_events', 0)}, "
                            f"causal_effect={it.get('causal_effect_score', 0.5):.0%}."
                        ),
                    }
                )
        alerts.sort(
            key=lambda a: (a["drift_score"], a["drift_events"]),
            reverse=True,
        )
        return alerts

    def summary_report(self) -> str:
        with self._lock:
            items = [copy.deepcopy(v) for v in self._entries.values()]
            recent = list(reversed(self._log[-15:]))
        alerts = self.drift_alerts()
        lines = ["=== CAUSAL COUNTERFACTUAL DRIFT & GUARD-EFFECT LEDGER ==="]
        if alerts:
            lines.append("Active Drift Alerts:")
            for a in alerts:
                lines.append(f"  ! {a['message']}")
        else:
            lines.append("No invariant drift alerts detected.")
        lines.append("")
        if not items:
            lines.append("No causal interventions recorded yet.")
        else:
            for it in sorted(
                items, key=lambda x: x.get("updated_at", ""), reverse=True
            ):
                lines.append(
                    f"  {it['flaw_id']} -> {it['target_name']} [{it['action']}]: "
                    f"causal_effect={it['causal_effect_score']:.0%}, "
                    f"verified={it['verified_runs']}, drift_events={it['drift_events']}, "
                    f"last_drift={it['last_drift_score']:.2f}"
                )
        if recent:
            lines.extend(["", "Recent Causal Deltas:"])
            for r in recent:
                lines.append(
                    f"  [{r['timestamp'][:19]}] {r['key']} | drift={r['drift_score']:.2f} | "
                    f"effect={r['causal_effect_score']:.0%} | {r.get('note', '')}"
                )
        return "\n".join(lines)


class ChainOfThoughtEngine:
    """
    Builds structured, multi-stage chain-of-thought reasoning with competing
    posterior hypotheses, regret-aware trade-off analysis across guard modes,
    mutation resilience, boundary invariant score, epistemic certainty, witness
    evasion pressure, counterfactual blast radius, and calibrated confidence.
    """

    @staticmethod
    def build_decision_plan(
        flaw: FlawRecord,
        target_name: str,
        evidence: str,
        learned_weight: float,
        memory_signal: dict[str, Any],
        causal_entry: Optional[dict[str, Any]] = None,
        resilience_ratio: float = 0.5,
        boundary_score: float = 55.0,
        epistemic_certainty: float = 50.0,
        witness_pressure: float = 25.0,
        blast_entry: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        sev_map = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.78,
            Severity.MEDIUM: 0.52,
            Severity.LOW: 0.28,
        }
        base_risk = sev_map[flaw.severity]
        mem_conf = float(memory_signal.get("confidence", 0.35))
        mem_prio = float(memory_signal.get("priority_score", 50.0)) / 100.0
        causal_eff = (
            float(causal_entry.get("causal_effect_score", 0.6))
            if isinstance(causal_entry, dict)
            else 0.6
        )
        boundary_norm = max(0.0, min(1.0, float(boundary_score) / 100.0))
        epistemic_norm = max(0.0, min(1.0, float(epistemic_certainty) / 100.0))
        witness_norm = max(0.0, min(1.0, float(witness_pressure) / 100.0))
        blast_norm = (
            max(0.0, min(1.0, float(blast_entry.get("selected_blast", 25.0)) / 100.0))
            if isinstance(blast_entry, dict)
            else 0.25
        )
        regret_norm = (
            max(0.0, min(1.0, float(blast_entry.get("min_regret", 25.0)) / 100.0))
            if isinstance(blast_entry, dict)
            else 0.25
        )

        raw_h_exp = base_risk * (0.75 + 0.25 * max(0.5, min(1.5, learned_weight)))
        raw_h_eva = (
            (1.0 - resilience_ratio) * 0.40
            + (1.0 - epistemic_norm) * 0.25
            + witness_norm * 0.20
            + regret_norm * 0.15
        )
        raw_h_ben = (1.0 - base_risk) * 0.45 + boundary_norm * 0.35 + blast_norm * 0.20
        z_sum = max(1e-6, raw_h_exp + raw_h_eva + raw_h_ben)
        post_h_exp = round(raw_h_exp / z_sum, 3)
        post_h_eva = round(raw_h_eva / z_sum, 3)
        post_h_ben = round(raw_h_ben / z_sum, 3)

        weight_stability = 1.0 - min(0.35, abs(learned_weight - 1.0) * 0.25)
        calibrated_confidence = round(
            max(
                0.20,
                min(
                    0.95,
                    0.18 * mem_conf
                    + 0.18 * causal_eff
                    + 0.15 * weight_stability
                    + 0.14 * max(0.1, min(1.0, resilience_ratio))
                    + 0.11 * boundary_norm
                    + 0.10 * epistemic_norm
                    + 0.07 * (1.0 - witness_norm)
                    + 0.07 * (1.0 - blast_norm),
                ),
            ),
            2,
        )

        block_utility = round(
            base_risk * 0.46
            + mem_prio * 0.16
            + (1.0 - resilience_ratio) * 0.11
            + (1.0 - epistemic_norm) * 0.09
            + witness_norm * 0.09
            + (1.0 - blast_norm) * 0.07,
            3,
        )
        sanitize_utility = round(
            (1.0 - base_risk * 0.35) * 0.34
            + causal_eff * 0.18
            + resilience_ratio * 0.13
            + boundary_norm * 0.12
            + epistemic_norm * 0.09
            + witness_norm * 0.07
            + (1.0 - regret_norm) * 0.07,
            3,
        )
        audit_utility = round(
            max(0.08, 0.72 - base_risk * 0.52 - mem_prio * 0.20),
            3,
        )

        if (
            flaw.severity in (Severity.CRITICAL, Severity.HIGH)
            or block_utility >= max(sanitize_utility, audit_utility)
        ):
            recommended = GuardAction.BLOCK
        elif sanitize_utility >= audit_utility:
            recommended = GuardAction.SANITIZE
        else:
            recommended = GuardAction.AUDIT

        chain_steps = [
            (
                "CoT-1 Hypothesis Posteriors",
                f"P(H_exploitable)={post_h_exp:.0%}, P(H_evasion)={post_h_eva:.0%}, "
                f"P(H_benign_fp)={post_h_ben:.0%} on '{target_name}' for {flaw.flaw_id}: {evidence[:100]}",
            ),
            (
                "CoT-2 Epistemic, Witness & Blast",
                f"Resilience={resilience_ratio:.0%}, boundary={boundary_score:.1f}/100, "
                f"epistemic={epistemic_certainty:.1f}/100, witness={witness_pressure:.1f}/100, "
                f"blast={blast_norm * 100:.1f}/100, regret={regret_norm * 100:.1f}/100.",
            ),
            (
                "CoT-3 Regret & Weight Synthesis",
                f"Utilities -> BLOCK={block_utility:.2f}, SANITIZE={sanitize_utility:.2f}, "
                f"AUDIT={audit_utility:.2f} | weight={learned_weight:.2f}, "
                f"causal_eff={causal_eff:.0%}, conf={calibrated_confidence:.0%}.",
            ),
        ]

        return {
            "recommended_action": recommended,
            "calibrated_confidence": calibrated_confidence,
            "posteriors": {
                "h_exploitable": post_h_exp,
                "h_evasion": post_h_eva,
                "h_benign_fp": post_h_ben,
            },
            "utilities": {
                "block": block_utility,
                "sanitize": sanitize_utility,
                "audit": audit_utility,
            },
            "chain_steps": chain_steps,
        }


class PredictiveForecastEngine:
    """
    Forward-looking predictive trajectory forecaster across horizons (24h, 7d, 30d):
    estimates recurrence risk, severity escalation probability, witness/boundary/epistemic/
    blast pressure, and proactive posture.
    """

    HORIZON_MULTIPLIERS: dict[str, float] = {
        "24H": 0.75,
        "7D": 1.00,
        "30D": 1.25,
    }

    @classmethod
    def forecast(
        cls,
        flaw: FlawRecord,
        learned_weight: float,
        memory_signal: dict[str, Any],
        drift_alerts: list[dict[str, Any]],
        resilience_ratio: float = 0.5,
        epistemic_certainty: float = 50.0,
        witness_pressure: float = 25.0,
        blast_pressure: float = 25.0,
        horizon: str = "7D",
    ) -> dict[str, Any]:
        h_key = (horizon or "7D").strip().upper()
        h_mult = cls.HORIZON_MULTIPLIERS.get(h_key, 1.0)

        seen = int(memory_signal.get("pattern_count", 0))
        novel = bool(memory_signal.get("novel", False))
        trend = str(memory_signal.get("trend", "BASELINE"))
        failed = int(memory_signal.get("failed", 0))
        worked = int(memory_signal.get("worked", 0))

        base_recurrence = (0.25 + min(0.45, math.log2(seen + 1) * 0.14)) * h_mult
        if trend == "RISING_SEVERE":
            base_recurrence += 0.16
        elif trend == "SHIFTING":
            base_recurrence += 0.09
        if novel:
            base_recurrence += 0.07
        if resilience_ratio < 0.5:
            base_recurrence += 0.06
        if epistemic_certainty < 50.0:
            base_recurrence += 0.05
        if witness_pressure >= 50.0:
            base_recurrence += 0.05
        if blast_pressure >= 65.0:
            base_recurrence += 0.04
        recurrence_prob = round(max(0.05, min(0.97, base_recurrence)), 2)

        sev_escalation = {
            Severity.LOW: 0.22,
            Severity.MEDIUM: 0.42,
            Severity.HIGH: 0.72,
            Severity.CRITICAL: 0.90,
        }[flaw.severity] * min(1.15, 0.85 + h_mult * 0.20)
        if trend == "RISING_SEVERE":
            sev_escalation = min(0.97, sev_escalation + 0.07)
        escalation_prob = round(sev_escalation, 2)

        weight_boost = max(0.80, min(1.25, learned_weight))
        drift_penalty = 0.09 * len(drift_alerts)
        forecast_confidence = round(
            max(
                0.25,
                min(
                    0.93,
                    float(memory_signal.get("confidence", 0.4))
                    + min(0.12, (worked + failed) * 0.03)
                    + resilience_ratio * 0.06
                    + (epistemic_certainty / 100.0) * 0.06
                    - drift_penalty,
                ),
            ),
            2,
        )
        forecast_index = round(
            min(
                100.0,
                ((recurrence_prob * 50.0 + escalation_prob * 50.0) * weight_boost)
                * (0.75 + 0.25 * forecast_confidence),
            ),
            1,
        )

        if forecast_index >= 70.0:
            posture = "PROACTIVE_BLOCK + WITNESS_REPAIR"
        elif forecast_index >= 45.0:
            posture = "SANITIZE + REGRET_WATCH"
        else:
            posture = "MONITOR_AND_AUDIT"

        rationale = [
            f"[{h_key} Horizon] Forecasted recurrence probability={recurrence_prob:.0%} "
            f"(seen={seen}, trend={trend}, novel={novel}, resilience={resilience_ratio:.0%}, "
            f"epistemic={epistemic_certainty:.0%}, witness={witness_pressure:.0f}%, blast={blast_pressure:.0f}%).",
            f"Severity escalation / impact index={escalation_prob:.0%} (NVD severity={flaw.severity.value.upper()}).",
            f"Confidence-adjusted forecast index={forecast_index}/100 (forecast_conf={forecast_confidence:.0%}, weight={learned_weight:.2f}).",
            f"Recommended posture: {posture}.",
        ]
        return {
            "horizon": h_key,
            "recurrence_probability": recurrence_prob,
            "escalation_probability": escalation_prob,
            "forecast_confidence": forecast_confidence,
            "forecast_index": forecast_index,
            "posture": posture,
            "rationale": rationale,
        }


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

    def fetch_cve_json(
        self, cve_id: str, force_download: bool = False
    ) -> dict[str, Any]:
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
        headers = {"User-Agent": "CVE-Flaw-Checker-TestBench/12.0"}
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
        for key in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
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

    def to_flaw_record(
        self, cve_id: str, force_download: bool = False
    ) -> FlawRecord:
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


@dataclass(frozen=True)
class PredictiveAssessment:
    """Explainable triage estimate; not proof that a host is vulnerable."""

    priority_score: float
    confidence: float
    weighted_score: float
    tier: str
    reasons: tuple[str, ...]


class PredictiveTriageEngine:
    """
    Deterministic, explainable prioritizer. It combines CVSS severity, available
    probe coverage, and exploit-related language. It deliberately does NOT claim
    host applicability because this application has no software/CPE inventory.
    """

    EXPLOIT_TERMS = (
        "remote code execution",
        "arbitrary code execution",
        "unauthenticated",
        "network reachable",
        "network attack",
        "privilege escalation",
        "authentication bypass",
        "actively exploited",
        "in the wild",
    )

    @classmethod
    def assess(
        cls, flaw: FlawRecord, learned_weight: float = 1.0
    ) -> PredictiveAssessment:
        severity_points = {
            Severity.LOW: 18.0,
            Severity.MEDIUM: 42.0,
            Severity.HIGH: 72.0,
            Severity.CRITICAL: 92.0,
        }[flaw.severity]
        description = flaw.description.lower()
        hits = [term for term in cls.EXPLOIT_TERMS if term in description]
        exploit_bonus = min(24.0, len(hits) * 6.0)
        probe_bonus = 8.0 if flaw.probe_name in PROBES else 0.0
        weight_factor = max(0.75, min(1.25, float(learned_weight)))
        score = min(
            100.0, (severity_points + exploit_bonus + probe_bonus) * weight_factor
        )

        confidence = 0.45
        if flaw.probe_name in PROBES:
            confidence += 0.20
        if flaw.description and len(flaw.description) >= 80:
            confidence += 0.10
        if hits:
            confidence += min(0.15, len(hits) * 0.03)
        confidence = round(min(0.90, confidence), 2)
        weighted_score = round(score * confidence, 1)

        tier = (
            "URGENT"
            if score >= 85
            else "HIGH"
            if score >= 65
            else ("MODERATE" if score >= 40 else "LOW")
        )
        reasons = [
            f"NVD severity contributes {severity_points:.0f}/100 base points."
        ]
        if hits:
            reasons.append(
                "Exploit-related indicators: " + ", ".join(hits[:5]) + "."
            )
        else:
            reasons.append("No configured exploit-language indicators were found.")
        reasons.append(
            "Automated probe coverage is available."
            if probe_bonus
            else "No automated probe exists; manual validation is required."
        )
        reasons.append(
            f"Confidence-weighted score={weighted_score:.1f} (raw={score:.1f} × conf={confidence:.0%})."
        )
        reasons.append(
            "Learned weight adjusts triage priority only; it does not prove applicability."
        )
        return PredictiveAssessment(
            round(score, 1), confidence, weighted_score, tier, tuple(reasons)
        )


class VulnerabilityEvolutionMemory:
    """Persistent, explainable memory of vulnerability families, temporal shifts,
    unusual characteristic combinations, recurring CVE comparisons, defense
    effectiveness, and failure-pattern alerts.

    An installed guard is NOT automatically counted as a successful defense;
    success/failure must be confirmed by the operator after a controlled test.
    """

    SCHEMA_VERSION = 2
    MAX_OBSERVATIONS = 5000
    MAX_CVE_HISTORY = 200

    FAMILY_TERMS = {
        "PATH_TRAVERSAL": (
            "path traversal",
            "directory traversal",
            "../",
            "file path",
        ),
        "COMMAND_INJECTION": (
            "command injection",
            "os command",
            "shell command",
            "command execution",
        ),
        "AUTH_BYPASS": (
            "authentication bypass",
            "authorization bypass",
            "improper authentication",
            "access control",
        ),
        "DESERIALIZATION": (
            "deserialization",
            "deserialize",
            "untrusted data",
        ),
        "MEMORY_CORRUPTION": (
            "buffer overflow",
            "use-after-free",
            "out-of-bounds",
            "memory corruption",
        ),
        "INJECTION": (
            "sql injection",
            "cross-site scripting",
            "injection",
        ),
        "INFO_DISCLOSURE": (
            "information disclosure",
            "sensitive information",
            "data leak",
        ),
        "CONFIG_EXPOSURE": (
            "misconfiguration",
            "default configuration",
            "improper configuration",
            "exposed interface",
        ),
    }

    CHARACTERISTIC_TAGS = (
        ("REMOTE_OR_NETWORK", ("remote", "network", "unauthenticated")),
        ("PRIVILEGE_ESCALATION", ("privilege", "escalation", "root", "admin")),
        ("CODE_EXECUTION", ("execution", "code execution", "shell", "rce")),
        ("BYPASS_MECHANISM", ("bypass", "circumvent", "skip check")),
        ("USER_INTERACTION", ("user interaction", "crafted input", "click", "visit")),
    )

    def __init__(self, storage_path: Path = DEFAULT_EVOLUTION_PATH) -> None:
        self.storage_path = Path(storage_path)
        self._lock = Lock()
        self._data: dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "patterns": {},
            "combinations": {},
            "unusual_combos": {},
            "defenses": {},
            "cve_history": {},
            "observations": [],
        }
        self._load()

    @classmethod
    def classify_family(cls, flaw: FlawRecord) -> str:
        text = f"{flaw.title} {flaw.description} {flaw.probe_name}".lower()
        for family, terms in cls.FAMILY_TERMS.items():
            if any(term in text for term in terms):
                return family
        probe = (flaw.probe_name or "").lower()
        if "path" in probe:
            return "PATH_TRAVERSAL"
        if "command" in probe:
            return "COMMAND_INJECTION"
        return "UNCLASSIFIED"

    @classmethod
    def extract_characteristics(cls, flaw: FlawRecord) -> list[str]:
        blob = f"{flaw.title} {flaw.description}".lower()
        tags = [
            tag
            for tag, terms in cls.CHARACTERISTIC_TAGS
            if any(t in blob for t in terms)
        ]
        if not tags:
            tags.append("STANDARD_TRAIT")
        return tags

    @staticmethod
    def _safe_key(value: str) -> str:
        return re.sub(r"[^A-Z0-9_.:-]+", "_", value.upper())[:180]

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                version = raw.get("schema_version", 1)
                if version in (1, self.SCHEMA_VERSION):
                    for key in (
                        "patterns",
                        "combinations",
                        "unusual_combos",
                        "defenses",
                        "cve_history",
                    ):
                        if isinstance(raw.get(key), dict):
                            self._data[key] = raw[key]
                    if isinstance(raw.get("observations"), list):
                        self._data["observations"] = raw["observations"][
                            -self.MAX_OBSERVATIONS :
                        ]
                    self._data["schema_version"] = self.SCHEMA_VERSION
        except (OSError, json.JSONDecodeError, TypeError):
            self._data["load_warning"] = (
                "Memory file could not be read; started with an empty memory."
            )

    def _save_locked(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.storage_path, self._data)

    @staticmethod
    def _compute_pattern_shift(
        history_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        n = len(history_events)
        if n < 2:
            return {
                "direction": "BASELINE",
                "delta": 0,
                "summary": f"Baseline sample ({n} observation(s)); need at least 2 for shift detection.",
            }
        half = max(1, n // 2)
        earlier = history_events[:-half] if n >= 3 else history_events[:1]
        recent = history_events[-half:]
        recent_crit_high = sum(
            1 for ev in recent if ev.get("severity") in ("CRITICAL", "HIGH")
        )
        earlier_crit_high = sum(
            1 for ev in earlier if ev.get("severity") in ("CRITICAL", "HIGH")
        )
        recent_rate = recent_crit_high / max(1, len(recent))
        earlier_rate = earlier_crit_high / max(1, len(earlier))
        severity_shift = round(recent_rate - earlier_rate, 2)

        recent_families = {
            ev.get("family") for ev in recent if ev.get("family")
        }
        earlier_families = {
            ev.get("family") for ev in earlier if ev.get("family")
        }
        new_fams = sorted(recent_families - earlier_families)

        if severity_shift >= 0.35 or (new_fams and len(recent) >= len(earlier)):
            direction = "RISING_SEVERE"
        elif abs(severity_shift) >= 0.25 or new_fams:
            direction = "SHIFTING"
        elif severity_shift <= -0.35:
            direction = "COOLING"
        else:
            direction = "STEADY"

        fam_note = (
            f"; new traits/families={', '.join(new_fams)}" if new_fams else ""
        )
        summary = (
            f"{direction}: recent high/crit share={recent_rate:.0%} vs earlier={earlier_rate:.0%}"
            f" (n={n}){fam_note}."
        )
        return {
            "direction": direction,
            "delta": severity_shift,
            "new_families": new_fams,
            "summary": summary,
        }

    def observe(
        self,
        flaw: FlawRecord,
        status: str,
        matches_count: int = 0,
        action_taken: str = "NONE",
        summary: str = "",
    ) -> dict[str, Any]:
        family = self.classify_family(flaw)
        traits = self.extract_characteristics(flaw)
        trait_sig = "+".join(traits[:3])
        pattern_key = self._safe_key(f"{family}::{flaw.probe_name}")
        combo_key = self._safe_key(
            f"{family}::{flaw.probe_name}::{flaw.severity.value}"
        )
        unusual_key = self._safe_key(
            f"{family}::{flaw.severity.value}::{trait_sig}"
        )
        now = datetime.now(timezone.utc).isoformat()
        sev_upper = flaw.severity.value.upper()

        with self._lock:
            patterns = self._data["patterns"]
            prior_pattern = patterns.get(pattern_key)
            is_new_pattern = not isinstance(prior_pattern, dict)
            pattern = (
                prior_pattern
                if isinstance(prior_pattern, dict)
                else {
                    "family": family,
                    "probe": flaw.probe_name,
                    "count": 0,
                    "cves": [],
                    "statuses": {},
                    "first_seen": now,
                    "last_seen": now,
                    "severity_counts": {},
                    "timeline": [],
                }
            )
            pattern["count"] = int(pattern.get("count", 0)) + 1
            pattern["last_seen"] = now
            if flaw.flaw_id not in pattern.setdefault("cves", []):
                pattern["cves"].append(flaw.flaw_id)
            pattern["cves"] = pattern["cves"][-100:]
            statuses = pattern.setdefault("statuses", {})
            statuses[status] = int(statuses.get(status, 0)) + 1
            sev_counts = pattern.setdefault("severity_counts", {})
            sev_counts[sev_upper] = int(sev_counts.get(sev_upper, 0)) + 1
            tl = pattern.setdefault("timeline", [])
            tl.append(
                {
                    "timestamp": now,
                    "cve_id": flaw.flaw_id,
                    "family": family,
                    "severity": sev_upper,
                    "status": status,
                }
            )
            pattern["timeline"] = tl[-120:]
            shift_info = self._compute_pattern_shift(pattern["timeline"])
            pattern["trend"] = shift_info["direction"]
            pattern["trend_summary"] = shift_info["summary"]
            patterns[pattern_key] = pattern

            combinations = self._data["combinations"]
            prior_combo = combinations.get(combo_key)
            is_novel_combo = not isinstance(prior_combo, dict)
            combo = (
                prior_combo
                if isinstance(prior_combo, dict)
                else {
                    "family": family,
                    "probe": flaw.probe_name,
                    "severity": sev_upper,
                    "count": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "cves": [],
                }
            )
            combo["count"] = int(combo.get("count", 0)) + 1
            combo["last_seen"] = now
            if flaw.flaw_id not in combo.setdefault("cves", []):
                combo["cves"].append(flaw.flaw_id)
            combo["cves"] = combo["cves"][-100:]
            combinations[combo_key] = combo

            unusual_map = self._data.setdefault("unusual_combos", {})
            prior_unusual = unusual_map.get(unusual_key)
            u_entry = (
                prior_unusual
                if isinstance(prior_unusual, dict)
                else {
                    "signature": f"{family} | {sev_upper} | {trait_sig}",
                    "family": family,
                    "severity": sev_upper,
                    "traits": traits,
                    "count": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "cves": [],
                }
            )
            u_entry["count"] = int(u_entry.get("count", 0)) + 1
            u_entry["last_seen"] = now
            if flaw.flaw_id not in u_entry.setdefault("cves", []):
                u_entry["cves"].append(flaw.flaw_id)
            u_entry["cves"] = u_entry["cves"][-100:]
            is_unusual = u_entry["count"] <= 2 and (
                (
                    sev_upper in ("CRITICAL", "HIGH")
                    and "STANDARD_TRAIT" not in traits
                )
                or (family == "UNCLASSIFIED")
                or (
                    flaw.probe_name == "manual_review"
                    and sev_upper == "CRITICAL"
                )
            )
            u_entry["unusual"] = is_unusual
            unusual_map[unusual_key] = u_entry

            cve_hist_map = self._data.setdefault("cve_history", {})
            cve_entry = cve_hist_map.get(flaw.flaw_id)
            if not isinstance(cve_entry, dict):
                cve_entry = {
                    "cve_id": flaw.flaw_id,
                    "family": family,
                    "probe_name": flaw.probe_name,
                    "title": flaw.title,
                    "first_seen": now,
                    "last_seen": now,
                    "observations": 0,
                    "severities": [],
                    "statuses": [],
                    "actions": [],
                    "history": [],
                }
            cve_entry["last_seen"] = now
            cve_entry["family"] = family
            cve_entry["probe_name"] = flaw.probe_name
            cve_entry["observations"] = (
                int(cve_entry.get("observations", 0)) + 1
            )
            if sev_upper not in cve_entry.setdefault("severities", []):
                cve_entry["severities"].append(sev_upper)
            if status not in cve_entry.setdefault("statuses", []):
                cve_entry["statuses"].append(status)
            if action_taken and action_taken not in cve_entry.setdefault(
                "actions", []
            ):
                cve_entry["actions"].append(action_taken)
            hist_list = cve_entry.setdefault("history", [])
            hist_list.append(
                {
                    "timestamp": now,
                    "severity": sev_upper,
                    "status": status,
                    "action_taken": action_taken,
                    "matches_count": int(matches_count),
                    "summary": str(summary)[:300],
                }
            )
            cve_entry["history"] = hist_list[-self.MAX_CVE_HISTORY :]
            cve_hist_map[flaw.flaw_id] = cve_entry

            observation = {
                "timestamp": now,
                "cve_id": flaw.flaw_id,
                "family": family,
                "traits": traits,
                "probe": flaw.probe_name,
                "severity": sev_upper,
                "status": status,
                "matches_count": int(matches_count),
                "action_taken": action_taken,
                "summary": str(summary)[:500],
                "new_pattern": is_new_pattern,
                "novel_combination": is_novel_combo,
                "unusual_combination": is_unusual,
                "trend": shift_info["direction"],
            }
            self._data["observations"].append(observation)
            self._data["observations"] = self._data["observations"][
                -self.MAX_OBSERVATIONS :
            ]
            self._save_locked()
            return {
                "family": family,
                "pattern_count": pattern["count"],
                "combination_count": combo["count"],
                "new_pattern": is_new_pattern,
                "novel_combination": is_novel_combo,
                "unusual_combination": is_unusual,
                "trend": shift_info["direction"],
                "trend_summary": shift_info["summary"],
            }

    def record_defense_feedback(
        self,
        flaw: FlawRecord,
        action: str,
        worked: bool,
        notes: str = "",
    ) -> dict[str, Any]:
        family = self.classify_family(flaw)
        action_key = self._safe_key(action)
        key = self._safe_key(f"{family}::{action_key}")
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            entry = self._data["defenses"].setdefault(
                key,
                {
                    "family": family,
                    "action": action_key,
                    "worked": 0,
                    "failed": 0,
                    "consecutive_failures": 0,
                    "cves": [],
                    "last_feedback": now,
                    "last_result": None,
                    "notes": "",
                },
            )
            if worked:
                entry["worked"] = int(entry.get("worked", 0)) + 1
                entry["consecutive_failures"] = 0
                entry["last_result"] = "WORKED"
            else:
                entry["failed"] = int(entry.get("failed", 0)) + 1
                entry["consecutive_failures"] = (
                    int(entry.get("consecutive_failures", 0)) + 1
                )
                entry["last_result"] = "FAILED"
            entry["last_feedback"] = now
            entry["last_cve"] = flaw.flaw_id
            entry["notes"] = str(notes)[:500]
            if flaw.flaw_id not in entry.setdefault("cves", []):
                entry["cves"].append(flaw.flaw_id)
            entry["cves"] = entry["cves"][-100:]
            self._data["observations"].append(
                {
                    "timestamp": now,
                    "cve_id": flaw.flaw_id,
                    "family": family,
                    "probe": flaw.probe_name,
                    "kind": "DEFENSE_FEEDBACK",
                    "action": action_key,
                    "result": "worked" if worked else "failed",
                    "consecutive_failures": entry["consecutive_failures"],
                    "notes": str(notes)[:300],
                }
            )
            self._data["observations"] = self._data["observations"][
                -self.MAX_OBSERVATIONS :
            ]
            self._save_locked()
            return copy.deepcopy(entry)

    def failure_alerts(
        self, family: Optional[str] = None
    ) -> list[dict[str, Any]]:
        with self._lock:
            defenses = [copy.deepcopy(v) for v in self._data["defenses"].values()]
        alerts: list[dict[str, Any]] = []
        for item in defenses:
            fam = item.get("family", "UNCLASSIFIED")
            if family and fam != family:
                continue
            worked = int(item.get("worked", 0))
            failed = int(item.get("failed", 0))
            streak = int(item.get("consecutive_failures", 0))
            total = worked + failed
            if total == 0 or failed == 0:
                continue
            fail_rate = failed / total
            if streak >= 2 or (total >= 2 and fail_rate >= 0.5):
                severity = (
                    "HIGH_ALERT"
                    if streak >= 2 or fail_rate >= 0.67
                    else "WARN"
                )
                alerts.append(
                    {
                        "severity": severity,
                        "family": fam,
                        "action": item.get("action", "UNKNOWN"),
                        "worked": worked,
                        "failed": failed,
                        "consecutive_failures": streak,
                        "failure_rate": round(fail_rate, 2),
                        "last_cve": item.get("last_cve", "N/A"),
                        "message": (
                            f"[{severity}] {fam} / {item.get('action')}: "
                            f"{failed}/{total} failed ({fail_rate:.0%}), streak={streak} "
                            f"(last CVE={item.get('last_cve', 'N/A')})."
                        ),
                    }
                )
        alerts.sort(
            key=lambda a: (a["consecutive_failures"], a["failure_rate"]),
            reverse=True,
        )
        return alerts

    def compare_recurring_cves(
        self, family: Optional[str] = None
    ) -> list[dict[str, Any]]:
        with self._lock:
            records = [
                copy.deepcopy(v)
                for v in self._data.get("cve_history", {}).values()
            ]
        recurring: list[dict[str, Any]] = []
        for rec in records:
            fam = rec.get("family", "UNCLASSIFIED")
            if family and fam != family:
                continue
            obs_count = int(rec.get("observations", 0))
            if obs_count < 2:
                continue
            hist = rec.get("history", [])
            first_sev = hist[0].get("severity", "N/A") if hist else "N/A"
            last_sev = hist[-1].get("severity", "N/A") if hist else "N/A"
            first_status = hist[0].get("status", "N/A") if hist else "N/A"
            last_status = hist[-1].get("status", "N/A") if hist else "N/A"
            sev_changed = first_sev != last_sev
            status_changed = first_status != last_status
            delta_note = []
            if sev_changed:
                delta_note.append(f"severity {first_sev} -> {last_sev}")
            if status_changed:
                delta_note.append(f"status {first_status} -> {last_status}")
            if not delta_note:
                delta_note.append(f"consistent ({last_sev}, {last_status})")
            recurring.append(
                {
                    "cve_id": rec.get("cve_id", ""),
                    "family": fam,
                    "probe_name": rec.get("probe_name", ""),
                    "observations": obs_count,
                    "first_seen": rec.get("first_seen", ""),
                    "last_seen": rec.get("last_seen", ""),
                    "severities": rec.get("severities", []),
                    "statuses": rec.get("statuses", []),
                    "actions": rec.get("actions", []),
                    "comparison": "; ".join(delta_note),
                }
            )
        recurring.sort(key=lambda r: (-r["observations"], r["cve_id"]))
        return recurring

    def unusual_combinations_list(self) -> list[dict[str, Any]]:
        with self._lock:
            unusual_map = copy.deepcopy(self._data.get("unusual_combos", {}))
            combo_map = copy.deepcopy(self._data.get("combinations", {}))
        items: list[dict[str, Any]] = []
        for entry in unusual_map.values():
            cnt = int(entry.get("count", 0))
            if entry.get("unusual") or cnt <= 2:
                items.append(entry)
        for c_entry in combo_map.values():
            if int(c_entry.get("count", 0)) == 1:
                items.append(
                    {
                        "signature": (
                            f"{c_entry.get('family')} | {c_entry.get('probe')} | "
                            f"{c_entry.get('severity')} (SINGLETON)"
                        ),
                        "family": c_entry.get("family"),
                        "severity": c_entry.get("severity"),
                        "traits": ["SINGLETON_COMBO"],
                        "count": 1,
                        "cves": c_entry.get("cves", []),
                        "unusual": True,
                    }
                )
        items.sort(
            key=lambda x: (int(x.get("count", 0)), x.get("signature", ""))
        )
        return items

    def prediction(self, flaw: FlawRecord) -> dict[str, Any]:
        family = self.classify_family(flaw)
        traits = self.extract_characteristics(flaw)
        pattern_key = self._safe_key(f"{family}::{flaw.probe_name}")
        combo_key = self._safe_key(
            f"{family}::{flaw.probe_name}::{flaw.severity.value}"
        )
        with self._lock:
            pattern = copy.deepcopy(
                self._data["patterns"].get(pattern_key, {})
            )
            combo = copy.deepcopy(
                self._data["combinations"].get(combo_key, {})
            )
            defenses = [
                copy.deepcopy(v)
                for v in self._data["defenses"].values()
                if v.get("family") == family
            ]
            cve_rec = copy.deepcopy(
                self._data.get("cve_history", {}).get(flaw.flaw_id, {})
            )

        seen = int(pattern.get("count", 0))
        cve_seen = int(cve_rec.get("observations", 0))
        new_combo = not bool(combo)
        worked = sum(int(x.get("worked", 0)) for x in defenses)
        failed = sum(int(x.get("failed", 0)) for x in defenses)
        feedback_n = worked + failed
        efficacy = (worked + 1) / (feedback_n + 2)
        recurrence = min(25.0, math.log2(seen + 1) * 7.0)
        failure_signal = (
            min(25.0, (failed / max(1, feedback_n)) * 25.0) if feedback_n else 0.0
        )
        novelty_signal = 18.0 if new_combo else 0.0
        trend = pattern.get("trend", "BASELINE")
        trend_bonus = (
            8.0
            if trend == "RISING_SEVERE"
            else (4.0 if trend == "SHIFTING" else 0.0)
        )
        priority = min(
            100.0,
            35.0 + recurrence + failure_signal + novelty_signal + trend_bonus,
        )
        confidence = round(
            min(
                0.90,
                0.35
                + min(0.35, seen * 0.05)
                + min(0.20, feedback_n * 0.05),
            ),
            2,
        )
        confidence_weighted_score = round(priority * confidence, 1)

        alerts = self.failure_alerts(family=family)
        reasons = [
            f"Confidence-weighted priority={confidence_weighted_score:.1f} (raw={priority:.1f} × conf={confidence:.0%}).",
            f"Pattern family {family} (traits={', '.join(traits)}): {seen} observation(s); trend={trend}.",
            (
                "New family/probe/severity combination: investigate for an emerging pattern."
                if new_combo
                else f"Combination previously observed {int(combo.get('count', 0))} time(s)."
            ),
        ]
        if cve_seen >= 2:
            reasons.append(
                f"Recurring CVE: {flaw.flaw_id} observed {cve_seen} time(s) historically."
            )
        if feedback_n:
            reasons.append(
                f"Recorded defense feedback: {worked} worked, {failed} failed; smoothed efficacy {efficacy:.0%}."
            )
        else:
            reasons.append(
                "No operator-confirmed defense results yet; efficacy is unknown."
            )
        if alerts:
            reasons.append(
                f"Failure-pattern alert active ({len(alerts)} alert(s)) for {family}; verify alternative controls."
            )
        elif failed:
            reasons.append(
                "Prior defense failures increase investigation priority; do not blindly reuse the same control."
            )
        return {
            "family": family,
            "traits": traits,
            "trend": trend,
            "trend_summary": pattern.get("trend_summary", "Baseline"),
            "priority_score": round(priority, 1),
            "confidence": confidence,
            "confidence_weighted_score": confidence_weighted_score,
            "novel": new_combo,
            "pattern_count": seen,
            "cve_observations": cve_seen,
            "worked": worked,
            "failed": failed,
            "efficacy": round(efficacy, 3),
            "failure_alerts": alerts,
            "reasons": reasons,
        }

    def defense_recommendation(self, flaw: FlawRecord) -> dict[str, Any]:
        family = self.classify_family(flaw)
        with self._lock:
            candidates = [
                copy.deepcopy(v)
                for v in self._data["defenses"].values()
                if v.get("family") == family
            ]
        ranked = []
        for item in candidates:
            worked = int(item.get("worked", 0))
            failed = int(item.get("failed", 0))
            streak = int(item.get("consecutive_failures", 0))
            total = worked + failed
            if total < 2:
                continue
            efficacy = (worked + 1) / (total + 2)
            adjusted = max(0.0, efficacy - streak * 0.12)
            ranked.append(
                (
                    adjusted,
                    efficacy,
                    total,
                    item.get("action", "AUDIT"),
                    worked,
                    failed,
                    streak,
                )
            )
        if not ranked:
            return {
                "action": None,
                "confidence": 0.0,
                "reason": "Insufficient operator-confirmed defense samples.",
            }
        _, efficacy, total, action, worked, failed, streak = max(
            ranked, key=lambda row: (row[0], row[1], row[2])
        )
        return {
            "action": action,
            "confidence": min(0.95, total / (total + 3)),
            "efficacy": efficacy,
            "samples": total,
            "worked": worked,
            "failed": failed,
            "consecutive_failures": streak,
            "reason": (
                f"Best recorded action for {family}: {action} worked {worked}/{total} times "
                f"(smoothed efficacy {efficacy:.0%}, fail_streak={streak})."
            ),
        }

    def report(self) -> str:
        with self._lock:
            patterns = copy.deepcopy(self._data["patterns"])
            combos = copy.deepcopy(self._data["combinations"])
            defenses = copy.deepcopy(self._data["defenses"])
            cve_history = copy.deepcopy(self._data.get("cve_history", {}))
            observations = len(self._data["observations"])
        alerts = self.failure_alerts()
        unusual = self.unusual_combinations_list()
        recurring = self.compare_recurring_cves()

        lines = [
            "=== VULNERABILITY EVOLUTION MEMORY ===",
            f"Stored observations: {observations} | tracked CVEs: {len(cve_history)}",
            f"Pattern families/probes: {len(patterns)} | combinations: {len(combos)}",
            "",
            "=== CHANGING PATTERNS OVER TIME ===",
        ]
        if not patterns:
            lines.append(
                "No patterns recorded yet. Run AI Automatic or process CVEs."
            )
        for item in sorted(
            patterns.values(),
            key=lambda x: int(x.get("count", 0)),
            reverse=True,
        )[:20]:
            trend_desc = item.get("trend_summary") or item.get(
                "trend", "BASELINE"
            )
            lines.append(
                f"{item.get('family')} / {item.get('probe')} (n={item.get('count', 0)}): "
                f"{trend_desc} | CVEs={', '.join(item.get('cves', [])[-8:])}"
            )

        lines.extend(["", "=== UNUSUAL & RARE COMBINATIONS ==="])
        if not unusual:
            lines.append("No unusual combinations flagged yet.")
        for u in unusual[:20]:
            lines.append(
                f"[UNUSUAL x{u.get('count', 1)}] {u.get('signature')} | CVEs={', '.join(u.get('cves', [])[-6:])}"
            )

        lines.extend(["", "=== RECURRING CVE HISTORICAL COMPARISONS ==="])
        if not recurring:
            lines.append("No recurring CVEs (2 or more observations) recorded yet.")
        for rec in recurring[:20]:
            lines.append(
                f"{rec['cve_id']} ({rec['family']}, x{rec['observations']}): {rec['comparison']}"
            )

        lines.extend(["", "=== DEFENSE EFFECTIVENESS & FAILURE ALERTS ==="])
        if alerts:
            for a in alerts:
                lines.append(f"  ALERT -> {a['message']}")
        else:
            lines.append("  No active defense failure-pattern alerts.")
        if not defenses:
            lines.append(
                "No defense feedback yet. Select a CVE in the catalog and record whether a tested defense worked or failed."
            )
        for item in sorted(
            defenses.values(),
            key=lambda x: int(x.get("worked", 0)) + int(x.get("failed", 0)),
            reverse=True,
        ):
            total = int(item.get("worked", 0)) + int(item.get("failed", 0))
            rate = (int(item.get("worked", 0)) + 1) / (total + 2)
            lines.append(
                f"{item.get('family')} / {item.get('action')}: worked={item.get('worked', 0)}, "
                f"failed={item.get('failed', 0)}, streak={item.get('consecutive_failures', 0)}, "
                f"smoothed={rate:.0%}"
            )

        lines.extend(
            [
                "",
                "Interpretation: evolution signals prioritize investigation; they do not establish exploitability or host exposure.",
            ]
        )
        return "\n".join(lines)

    def export_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)


# Live test-bench targets (no OS command execution; sandboxed path resolution)
weight_store = LearningWeightStore()
registry = GuardRegistry(weights=weight_store)
rollback_ledger = RollbackLedger()
evolution_memory = VulnerabilityEvolutionMemory()
causal_drift = CausalDriftEngine()
mutation_lattice = MutationLatticeEngine()
boundary_engine = BoundaryGrammarEngine()
epistemic_cartographer = EpistemicCartographer()
witness_engine = InvariantWitnessEngine()
blast_regret_engine = BlastRadiusRegretEngine()


def ensure_sandbox_dir(sandbox_dir: Path = DEFAULT_SANDBOX_DIR) -> Path:
    root = Path(sandbox_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sample = root / "bench_manifest.json"
    if not sample.exists():
        sample.write_text(
            json.dumps({"bench": "active", "status": "ok"}, indent=2),
            encoding="utf-8",
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


def _iter_string_inputs(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> list[str]:
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
        min_confidence: float = 0.35,
        max_blast_radius: float = 80.0,
        harden_mutations: bool = True,
        auto_heal: bool = True,
        auto_witness: bool = True,
        auto_regret: bool = True,
        forecast_horizon: str = "7D",
    ) -> None:
        self.registry = registry
        self.catalog = catalog
        self.weights = weights or registry.weights or LearningWeightStore()
        self.ledger = ledger
        self.min_confidence = max(0.10, min(0.95, float(min_confidence)))
        self.max_blast_radius = max(10.0, min(100.0, float(max_blast_radius)))
        self.harden_mutations = bool(harden_mutations)
        self.auto_heal = bool(auto_heal)
        self.auto_witness = bool(auto_witness)
        self.auto_regret = bool(auto_regret)
        self.forecast_horizon = (forecast_horizon or "7D").strip().upper()

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
        resilience = mutation_lattice.get_resilience(
            match.flaw.flaw_id, match.target_name
        )
        b_score = boundary_engine.get_boundary_score(
            match.flaw.flaw_id, match.target_name
        )
        e_cert = epistemic_cartographer.get_certainty(
            match.flaw.flaw_id, match.target_name
        )
        w_press = witness_engine.get_evasion_pressure(
            match.flaw.flaw_id, match.target_name
        )
        blast_info = BlastRadiusRegretEngine.evaluate_regret(
            match.flaw,
            match.target_name,
            self.registry.rules_for(match.target_name),
            learned_weight=w,
            resilience_ratio=resilience,
            witness_pressure=w_press,
            persist=self.auto_regret,
        )
        blast_press = float(blast_info.get("selected_blast", 25.0))
        prediction = PredictiveTriageEngine.assess(match.flaw, w)
        memory_signal = evolution_memory.prediction(match.flaw)
        defense_history = evolution_memory.defense_recommendation(match.flaw)
        drift_alerts = causal_drift.drift_alerts()
        forecast = PredictiveForecastEngine.forecast(
            match.flaw,
            w,
            memory_signal,
            drift_alerts,
            resilience,
            e_cert,
            w_press,
            blast_pressure=blast_press,
            horizon=self.forecast_horizon,
        )

        cot_plan = ChainOfThoughtEngine.build_decision_plan(
            flaw=match.flaw,
            target_name=match.target_name,
            evidence=match.evidence,
            learned_weight=w,
            memory_signal=memory_signal,
            resilience_ratio=resilience,
            boundary_score=b_score,
            epistemic_certainty=e_cert,
            witness_pressure=w_press,
            blast_entry=blast_info,
        )

        if trace:
            for stage_name, stage_detail in cot_plan["chain_steps"]:
                trace.add(stage_name, stage_detail)
            trace.add(
                "Predictive Triage + Forecast",
                f"Base priority={prediction.priority_score:.1f}/100 ({prediction.tier}), "
                f"conf-weighted={prediction.weighted_score:.1f}; "
                f"evolution conf-weighted={memory_signal['confidence_weighted_score']:.1f}; "
                f"forecast_index[{forecast['horizon']}]={forecast['forecast_index']}/100 "
                f"(recurrence={forecast['recurrence_probability']:.0%}, "
                f"escalation={forecast['escalation_probability']:.0%}, posture={forecast['posture']}). "
                + " ".join(prediction.reasons + tuple(memory_signal["reasons"])),
            )
            for alert in memory_signal.get("failure_alerts") or []:
                trace.add("Failure Alert", alert["message"])

        sev_score = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.45,
            Severity.LOW: 0.2,
        }[match.flaw.severity]
        conf_weighted_norm = memory_signal["confidence_weighted_score"] / 100.0
        memory_factor = 0.85 + conf_weighted_norm * 0.30
        effective_score = round(sev_score * w * memory_factor, 4)

        action = cot_plan["recommended_action"]
        if (
            match.flaw.severity in (Severity.CRITICAL, Severity.HIGH)
            or effective_score >= 0.7
        ):
            action = GuardAction.BLOCK
        elif effective_score >= 0.35 and action == GuardAction.AUDIT:
            action = GuardAction.SANITIZE

        block_blast_val = float(
            (blast_info.get("blast_radius") or {}).get("block", 25.0)
        )
        if (
            self.auto_regret
            and action == GuardAction.BLOCK
            and match.flaw.severity != Severity.CRITICAL
            and block_blast_val > self.max_blast_radius
        ):
            action = GuardAction.SANITIZE
            if trace:
                trace.add(
                    "Blast-Radius Regret Gate",
                    f"BLOCK blast radius {block_blast_val:.1f} > cap {self.max_blast_radius:.1f} "
                    f"(min_regret={blast_info['min_regret']:.1f}); stepped down to SANITIZE.",
                )

        if (
            cot_plan["calibrated_confidence"] < self.min_confidence
            and match.flaw.severity != Severity.CRITICAL
            and action == GuardAction.BLOCK
        ):
            action = GuardAction.SANITIZE
            if trace:
                trace.add(
                    "Confidence Gate",
                    f"Calibrated confidence {cot_plan['calibrated_confidence']:.0%} < threshold "
                    f"{self.min_confidence:.0%}; stepped down to SANITIZE.",
                )

        learned_action = defense_history.get("action")
        if learned_action and defense_history.get("confidence", 0.0) >= 0.40:
            try:
                learned_enum = GuardAction(learned_action.lower())
                if learned_enum != action:
                    action = learned_enum
                    if trace:
                        trace.add(
                            "Defense Evolution",
                            defense_history["reason"]
                            + " Selected from confirmed history instead of the severity-only default.",
                        )
            except ValueError:
                pass

        if trace:
            trace.add(
                "Reasoning & Weighting",
                f"Computed effective_score={effective_score:.3f} "
                f"(severity={match.flaw.severity.value}, learned weight={w:.2f}, "
                f"memory factor={memory_factor:.2f}, cot_conf={cot_plan['calibrated_confidence']:.0%}) "
                f"-> selected action={action.value.upper()}.",
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

            w = self.weights.get_weight(
                match.flaw.flaw_id, match.target_name, match.flaw.probe_name
            )
            chosen_action, priority = (
                (action, w)
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
            matched_count = sum(1 for r in sim_rows if r["matched"] == "yes")
            hit_rate = matched_count / max(1, len(sim_rows))
            if trace:
                trace.add(
                    "Counterfactual Sim",
                    f"Simulated {len(sim_rows)} test inputs ({matched_count} pattern matches, "
                    f"hit_rate={hit_rate:.0%}) for {match.target_name} under {chosen_action.value.upper()}.",
                )

            def predicate(
                *args: Any, _regex=compiled, **kwargs: Any
            ) -> bool:
                for candidate in _iter_string_inputs(args, kwargs):
                    decoded = RemediationEngine._decode_iterative(candidate)
                    if _regex.search(candidate) or _regex.search(decoded):
                        return True
                return False

            verb = (
                "Blocked"
                if chosen_action == GuardAction.BLOCK
                else (
                    "Sanitized"
                    if chosen_action == GuardAction.SANITIZE
                    else "Audited"
                )
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

            lat = MutationLatticeEngine.evaluate_lattice(
                match.flaw,
                match.target_name,
                self.registry.rules_for(match.target_name),
                persist=True,
            )
            b_res = BoundaryGrammarEngine.verify_boundaries(
                match.flaw,
                match.target_name,
                self.registry.rules_for(match.target_name),
                persist=True,
            )
            e_map = EpistemicCartographer.map_epistemic_space(
                match.flaw,
                match.target_name,
                self.registry.rules_for(match.target_name),
                learned_weight=w,
                persist=True,
            )
            w_syn = InvariantWitnessEngine.synthesize_witness(
                match.flaw,
                match.target_name,
                self.registry.rules_for(match.target_name),
                learned_weight=w,
                persist=self.auto_witness,
            )
            br_res = BlastRadiusRegretEngine.evaluate_regret(
                match.flaw,
                match.target_name,
                self.registry.rules_for(match.target_name),
                learned_weight=w,
                resilience_ratio=lat["resilience_ratio"],
                witness_pressure=w_syn["evasion_pressure"],
                persist=self.auto_regret,
            )

            if (self.harden_mutations or self.auto_heal) and (
                lat["missed_threats"]
                or b_res["violations"]
                or e_map["blind_classes"]
                or w_syn["evading_count"] > 0
                or br_res["min_regret"] >= 50.0
            ):
                hardened_san = RemediationEngine.build_sanitizer(match.flaw)
                self.registry.register(
                    GuardRule(
                        name=f"heal_{match.flaw.flaw_id.lower()}",
                        target_name=match.target_name,
                        predicate=predicate,
                        action=GuardAction.SANITIZE,
                        flaw_id=match.flaw.flaw_id,
                        reason=f"Epistemic, witness, regret & boundary self-healing sanitizer for {match.flaw.flaw_id}",
                        priority=max(0.1, priority - 0.05),
                        block_pattern=match.flaw.block_pattern,
                        sanitizer=hardened_san,
                    )
                )
                posted += 1
                if trace:
                    trace.add(
                        "Self-Healing Remediation",
                        f"Added companion SANITIZE rule on {match.target_name} "
                        f"(missed_mutations={len(lat['missed_threats'])}, "
                        f"boundary_violations={len(b_res['violations'])}, "
                        f"blind_classes={e_map['blind_classes']}, "
                        f"witness={w_syn['minimal_witness']!r}, "
                        f"regret={br_res['min_regret']:.1f}).",
                    )

            causal_info = causal_drift.record_intervention(
                flaw_id=match.flaw.flaw_id,
                target_name=match.target_name,
                action=chosen_action.value,
                pre_matched=True,
                counterfactual_hit_rate=hit_rate,
                post_verified_intercepted=None,
                note=f"Applied {chosen_action.value.upper()} rule (prio={priority:.2f}, regret={br_res['min_regret']:.1f})",
            )

            diagnostics = RuleDiagnostics.analyze_target(
                match.target_name, self.registry.rules_for(match.target_name)
            )
            if trace:
                trace.add(
                    "Fix Applied",
                    f"Registered {chosen_action.value.upper()} guard on {match.target_name} "
                    f"for {match.flaw.flaw_id} (priority={priority:.2f}, "
                    f"lattice_score={lat['lattice_score']}/100, "
                    f"boundary_score={b_res['boundary_score']}/100, "
                    f"epistemic_certainty={e_map['epistemic_certainty']}/100, "
                    f"witness_pressure={w_syn['evasion_pressure']}/100, "
                    f"blast={br_res['selected_blast']}/100, regret={br_res['min_regret']}/100, "
                    f"causal_effect={causal_info['causal_effect_score']:.0%}).",
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
        self.geometry("1400x940")
        self.minsize(1000, 680)
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
            "counterfactual simulation, mutation resilience lattice, boundary grammar verifier, "
            "epistemic equivalence-class blind-spot cartographer, minimal counterexample witness "
            "& structural repair synthesizer, blast-radius & regret minimizer, rollback ledger, "
            "learning weights, reasoning traces, Vulnerability Evolution Memory, Causal Drift Ledger "
            "& Multi-Horizon Forecaster."
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
        style.configure(
            "TCheckbutton", background="#111827", foreground="#e5e7eb"
        )
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 17, "bold"),
            foreground="#f9fafb",
        )
        style.configure(
            "SubTitle.TLabel",
            font=("Segoe UI", 11, "bold"),
            foreground="#f3f4f6",
        )
        style.configure("TButton", padding=7)
        style.configure(
            "Treeview",
            rowheight=25,
            background="#1f2937",
            fieldbackground="#1f2937",
            foreground="#f9fafb",
        )
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        header = ttk.Frame(self, padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(
            header, text="CVE TEST BENCH WORKBENCH", style="Title.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Live NVD 2.0 • batch queue • bench targets • guards • mutation lattice • boundary grammar • epistemic cartographer • witness synthesizer • blast & regret • rollback ledger • weights • causal drift • AI Automatic",
        ).pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self, padding=(16, 4))
        controls.pack(fill="x")
        ttk.Label(controls, text="CVE ID(s)").pack(side="left")
        self.cve_var = tk.StringVar(value="CVE-2021-41773")
        entry = ttk.Entry(controls, textvariable=self.cve_var, width=22)
        entry.pack(side="left", padx=(6, 6))
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
        self.refresh_btn.pack(side="left", padx=4)

        ttk.Label(controls, text="Policy:").pack(side="left", padx=(6, 2))
        self.policy_mode_var = tk.StringVar(value="AUTO")
        ttk.Combobox(
            controls,
            textvariable=self.policy_mode_var,
            values=("AUTO", "BLOCK", "SANITIZE", "AUDIT"),
            state="readonly",
            width=8,
        ).pack(side="left")

        ttk.Label(controls, text="Scope:").pack(side="left", padx=(6, 2))
        self.target_scope_var = tk.StringVar(value="ALL")
        ttk.Combobox(
            controls,
            textvariable=self.target_scope_var,
            values=("ALL", "PATH_ONLY", "CMD_ONLY"),
            state="readonly",
            width=10,
        ).pack(side="left")

        ttk.Label(controls, text="Horizon:").pack(side="left", padx=(6, 2))
        self.horizon_var = tk.StringVar(value="7D")
        ttk.Combobox(
            controls,
            textvariable=self.horizon_var,
            values=("24H", "7D", "30D"),
            state="readonly",
            width=5,
        ).pack(side="left")

        ttk.Label(controls, text="MinConf:").pack(side="left", padx=(6, 2))
        self.min_conf_var = tk.StringVar(value="0.35")
        ttk.Combobox(
            controls,
            textvariable=self.min_conf_var,
            values=("0.25", "0.35", "0.50", "0.70"),
            state="readonly",
            width=6,
        ).pack(side="left")

        ttk.Label(controls, text="BlastCap:").pack(side="left", padx=(6, 2))
        self.blast_cap_var = tk.StringVar(value="80")
        ttk.Combobox(
            controls,
            textvariable=self.blast_cap_var,
            values=("50", "65", "80", "100"),
            state="readonly",
            width=4,
        ).pack(side="left")

        ttk.Label(controls, text="Delay:").pack(side="left", padx=(6, 2))
        self.batch_delay_var = tk.StringVar(value="2s")
        ttk.Combobox(
            controls,
            textvariable=self.batch_delay_var,
            values=("0s", "2s", "6s"),
            state="readonly",
            width=4,
        ).pack(side="left")

        self.ai_auto_btn = ttk.Button(
            controls, text="AI Automatic", command=self.toggle_ai_automatic
        )
        self.ai_auto_btn.pack(side="left", padx=(6, 0))

        ttk.Button(
            controls, text="Cache folder", command=self.open_cache_folder
        ).pack(side="right")

        options_row = ttk.Frame(self, padding=(16, 2))
        options_row.pack(fill="x")
        self.loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_row, text="Auto-repeat (30s)", variable=self.loop_var
        ).pack(side="left", padx=(0, 8))

        # Safe-by-default: autonomous analysis never changes guard policy unless
        # the operator explicitly enables this option.
        self.auto_apply_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_row,
            text="Allow auto-install guards",
            variable=self.auto_apply_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_tune_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Auto-tune weights",
            variable=self.auto_tune_var,
        ).pack(side="left", padx=(0, 8))

        self.harden_mutations_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Mutation hardening",
            variable=self.harden_mutations_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_heal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Auto-heal rules",
            variable=self.auto_heal_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_witness_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Auto-witness scan",
            variable=self.auto_witness_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_regret_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Auto-regret guard",
            variable=self.auto_regret_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row,
            text="Auto-verify after install",
            variable=self.auto_verify_var,
        ).pack(side="left", padx=(0, 8))

        self.auto_rollback_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_row,
            text="Auto-rollback on drift",
            variable=self.auto_rollback_var,
        ).pack(side="left", padx=(0, 8))

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.status_var, padding=(16, 3)).pack(
            fill="x"
        )
        ttk.Label(
            self,
            text="Predictive scores prioritize investigation; verify installed product, "
            "version, configuration and vendor advisories before treating a CVE as applicable.",
            foreground="#fbbf24",
            wraplength=1340,
        ).pack(fill="x", padx=16, pady=(0, 3))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=6)
        catalog_tab = ttk.Frame(notebook, padding=10)
        detail_tab = ttk.Frame(notebook, padding=10)
        guard_tab = ttk.Frame(notebook, padding=10)
        outcomes_tab = ttk.Frame(notebook, padding=10)
        reasoning_tab = ttk.Frame(notebook, padding=10)
        evolution_tab = ttk.Frame(notebook, padding=10)
        causal_tab = ttk.Frame(notebook, padding=10)
        mutation_tab = ttk.Frame(notebook, padding=10)
        boundary_tab = ttk.Frame(notebook, padding=10)
        epistemic_tab = ttk.Frame(notebook, padding=10)
        witness_tab = ttk.Frame(notebook, padding=10)
        blast_tab = ttk.Frame(notebook, padding=10)
        ledger_tab = ttk.Frame(notebook, padding=10)
        events_tab = ttk.Frame(notebook, padding=10)
        log_tab = ttk.Frame(notebook, padding=10)
        notebook.add(catalog_tab, text="CVE Catalog")
        notebook.add(detail_tab, text="CVE Details")
        notebook.add(guard_tab, text="Test Bench & Guards")
        notebook.add(outcomes_tab, text="Batch Outcomes")
        notebook.add(reasoning_tab, text="Reasoning & Weights")
        notebook.add(evolution_tab, text="Evolution Memory")
        notebook.add(causal_tab, text="Causal Drift & Forecast")
        notebook.add(mutation_tab, text="Mutation Lattice")
        notebook.add(boundary_tab, text="Boundary & Grammar")
        notebook.add(epistemic_tab, text="Epistemic Cartography")
        notebook.add(witness_tab, text="Witness & Repair")
        notebook.add(blast_tab, text="Blast Radius & Regret")
        notebook.add(ledger_tab, text="Counterfactual & Ledger")
        notebook.add(events_tab, text="Guard Events")
        notebook.add(log_tab, text="Activity Log")

        self.tree = ttk.Treeview(
            catalog_tab,
            columns=("severity", "probe", "title"),
            show="headings",
            height=12,
        )
        for col, heading, width in (
            ("severity", "Severity", 100),
            ("probe", "Suggested check", 210),
            ("title", "Description summary", 840),
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
        self.details.insert(
            "1.0", "Fetch a CVE to view its NVD description and metadata."
        )
        self.details.configure(state="disabled")

        ttk.Label(
            guard_tab,
            text="Live Test-Bench Targets & Guards",
            style="Title.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            guard_tab,
            text=(
                "Evaluates and guards resolve_bench_path() and parse_bench_command_tokens() "
                "using @registry.protect rules (BLOCK, SANITIZE, AUDIT)."
            ),
            wraplength=1200,
        ).pack(anchor="w", pady=6)

        buttons = ttk.Frame(guard_tab)
        buttons.pack(anchor="w", pady=6)
        ttk.Button(
            buttons, text="Run bench checks", command=self.run_bench_checks
        ).pack(side="left")
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
            buttons,
            text="Install AUDIT guards",
            command=lambda: self.install_guards(GuardAction.AUDIT),
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
            ("summary", "Per-CVE details", 640),
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

        evolution_controls = ttk.Frame(evolution_tab)
        evolution_controls.pack(fill="x")
        ttk.Button(
            evolution_controls,
            text="Refresh memory",
            command=self.refresh_evolution_view,
        ).pack(side="left")
        ttk.Label(evolution_controls, text="Defense tested:").pack(
            side="left", padx=(14, 4)
        )
        self.evolution_action_var = tk.StringVar(value="BLOCK")
        ttk.Combobox(
            evolution_controls,
            textvariable=self.evolution_action_var,
            values=("BLOCK", "SANITIZE", "AUDIT", "OTHER"),
            state="readonly",
            width=12,
        ).pack(side="left")
        ttk.Button(
            evolution_controls,
            text="Record WORKED",
            command=lambda: self.record_evolution_feedback(True),
        ).pack(side="left", padx=6)
        ttk.Button(
            evolution_controls,
            text="Record FAILED",
            command=lambda: self.record_evolution_feedback(False),
        ).pack(side="left")
        ttk.Button(
            evolution_controls,
            text="Export memory JSON",
            command=self.export_evolution_memory,
        ).pack(side="right")

        ttk.Label(
            evolution_tab,
            text=(
                "Select a CVE in the CVE Catalog before recording defense feedback. "
                "Only operator-confirmed test results train defense efficacy; installing a guard alone is not success."
            ),
            wraplength=1240,
            foreground="#fbbf24",
        ).pack(anchor="w", pady=(6, 4))

        evo_split = ttk.PanedWindow(evolution_tab, orient="vertical")
        evo_split.pack(fill="both", expand=True)

        top_evo = ttk.Frame(evo_split)
        ttk.Label(
            top_evo,
            text="Persistent Historical CVE Records & Recurring Comparisons",
            style="SubTitle.TLabel",
        ).pack(anchor="w", pady=(0, 4))
        self.evolution_history_tree = ttk.Treeview(
            top_evo,
            columns=("cve", "family", "obs", "severities", "statuses", "comparison"),
            show="headings",
            height=6,
        )
        for col, heading, width in (
            ("cve", "CVE ID", 145),
            ("family", "Family", 165),
            ("obs", "Seen", 65),
            ("severities", "Severities", 130),
            ("statuses", "Statuses", 170),
            ("comparison", "Historical Comparison", 590),
        ):
            self.evolution_history_tree.heading(col, text=heading)
            self.evolution_history_tree.column(col, width=width, anchor="w")
        self.evolution_history_tree.pack(fill="both", expand=True)
        evo_split.add(top_evo, weight=1)

        bot_evo = ttk.Frame(evo_split)
        ttk.Label(
            bot_evo,
            text="Confidence-Weighted Predictions, Pattern Shifts, Unusual Combinations & Failure Alerts",
            style="SubTitle.TLabel",
        ).pack(anchor="w", pady=(4, 4))
        self.evolution_text = tk.Text(
            bot_evo,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.evolution_text.pack(fill="both", expand=True)
        evo_split.add(bot_evo, weight=2)
        self.refresh_evolution_view()

        causal_controls = ttk.Frame(causal_tab)
        causal_controls.pack(fill="x")
        ttk.Button(
            causal_controls,
            text="Refresh causal drift & forecast",
            command=self.refresh_causal_forecast_view,
        ).pack(side="left")
        ttk.Button(
            causal_controls,
            text="Run verify & bind causal delta",
            command=self.verify_guards,
        ).pack(side="left", padx=6)

        self.causal_text = tk.Text(
            causal_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.causal_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_causal_forecast_view()

        mutation_controls = ttk.Frame(mutation_tab)
        mutation_controls.pack(fill="x")
        ttk.Button(
            mutation_controls,
            text="Run mutation resilience scan",
            command=self.run_mutation_lattice_scan,
        ).pack(side="left")

        self.mutation_text = tk.Text(
            mutation_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.mutation_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_mutation_view()

        boundary_controls = ttk.Frame(boundary_tab)
        boundary_controls.pack(fill="x")
        ttk.Button(
            boundary_controls,
            text="Run boundary & grammar verification",
            command=self.run_boundary_grammar_scan,
        ).pack(side="left")

        self.boundary_text = tk.Text(
            boundary_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.boundary_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_boundary_view()

        epistemic_controls = ttk.Frame(epistemic_tab)
        epistemic_controls.pack(fill="x")
        ttk.Button(
            epistemic_controls,
            text="Run epistemic cartography",
            command=self.run_epistemic_cartography,
        ).pack(side="left")

        self.epistemic_text = tk.Text(
            epistemic_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.epistemic_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_epistemic_view()

        witness_controls = ttk.Frame(witness_tab)
        witness_controls.pack(fill="x")
        ttk.Button(
            witness_controls,
            text="Synthesize counterexample witnesses",
            command=self.run_witness_synthesis,
        ).pack(side="left")

        self.witness_text = tk.Text(
            witness_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.witness_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_witness_view()

        blast_controls = ttk.Frame(blast_tab)
        blast_controls.pack(fill="x")
        ttk.Button(
            blast_controls,
            text="Evaluate blast radius & regret",
            command=self.run_blast_regret_scan,
        ).pack(side="left")

        self.blast_text = tk.Text(
            blast_tab,
            wrap="word",
            bg="#1f2937",
            fg="#f9fafb",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.blast_text.pack(fill="both", expand=True, pady=(8, 0))
        self.refresh_blast_view()

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
        ttk.Label(ledger_controls, text="Checkpoint ID:").pack(
            side="left", padx=(12, 4)
        )
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
            event_buttons,
            text="Export events JSON",
            command=self.export_events_json,
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

    def _selected_policy_action(self) -> Optional[GuardAction]:
        mode = (self.policy_mode_var.get() or "AUTO").strip().upper()
        if mode == "BLOCK":
            return GuardAction.BLOCK
        if mode == "SANITIZE":
            return GuardAction.SANITIZE
        if mode == "AUDIT":
            return GuardAction.AUDIT
        return None

    def _scoped_targets(self) -> tuple[Callable[..., Any], ...]:
        scope = (self.target_scope_var.get() or "ALL").strip().upper()
        if scope == "PATH_ONLY":
            return (resolve_bench_path,)
        if scope == "CMD_ONLY":
            return (parse_bench_command_tokens,)
        return (resolve_bench_path, parse_bench_command_tokens)

    def _min_confidence(self) -> float:
        try:
            return float(self.min_conf_var.get())
        except (TypeError, ValueError):
            return 0.35

    def _blast_cap(self) -> float:
        try:
            return max(10.0, min(100.0, float(self.blast_cap_var.get())))
        except (TypeError, ValueError):
            return 80.0

    def _horizon(self) -> str:
        return (self.horizon_var.get() or "7D").strip().upper()

    def _batch_delay_seconds(self) -> float:
        raw = (self.batch_delay_var.get() or "2s").strip().lower().rstrip("s")
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return 2.0

    def _build_controller(
        self, catalog: list[FlawRecord]
    ) -> FlawGuardController:
        return FlawGuardController(
            registry,
            catalog,
            weights=weight_store,
            ledger=rollback_ledger,
            min_confidence=self._min_confidence(),
            max_blast_radius=self._blast_cap(),
            harden_mutations=bool(self.harden_mutations_var.get()),
            auto_heal=bool(self.auto_heal_var.get()),
            auto_witness=bool(self.auto_witness_var.get()),
            auto_regret=bool(self.auto_regret_var.get()),
            forecast_horizon=self._horizon(),
        )

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
        record = next(
            (item for item in self.catalog if item.flaw_id == outcome.cve_id),
            None,
        )
        if record is not None:
            try:
                insight = evolution_memory.observe(
                    record,
                    outcome.status,
                    outcome.matches_count,
                    outcome.action_taken,
                    outcome.summary,
                )
                extra_flags = []
                if insight.get("unusual_combination"):
                    extra_flags.append("UNUSUAL_COMBO")
                if insight.get("trend") not in ("BASELINE", "STEADY"):
                    extra_flags.append(f"TREND={insight.get('trend')}")
                flag_str = (
                    f" [{', '.join(extra_flags)}]" if extra_flags else ""
                )
                self._log(
                    f"Evolution memory: {insight['family']} pattern count={insight['pattern_count']}; "
                    f"novel combination={insight['novel_combination']}{flag_str}."
                )
                for alert in evolution_memory.failure_alerts(
                    family=insight["family"]
                ):
                    self._log(f"Defense Failure Alert: {alert['message']}")
            except OSError as exc:
                self._log(f"Evolution memory save warning: {exc}")
            self.refresh_evolution_view()
            self.refresh_causal_forecast_view()
            self.refresh_mutation_view()
            self.refresh_boundary_view()
            self.refresh_epistemic_view()
            self.refresh_witness_view()
            self.refresh_blast_view()
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
        auto_verify = bool(self.auto_verify_var.get())
        override_action = self._selected_policy_action()
        targets = self._scoped_targets()
        min_conf = self._min_confidence()
        blast_cap = self._blast_cap()
        harden_mut = bool(self.harden_mutations_var.get())
        auto_heal = bool(self.auto_heal_var.get())
        auto_witness = bool(self.auto_witness_var.get())
        auto_regret = bool(self.auto_regret_var.get())
        horizon = self._horizon()
        delay_sec = self._batch_delay_seconds()

        self._stop_auto.clear()
        self._auto_running = True
        self.ai_auto_btn.configure(text="Stop AI Auto")
        self.fetch_btn.configure(state="disabled")
        self.refresh_btn.configure(state="disabled")
        self._log(
            f"AI Automatic started for batch queue ({len(cve_queue)} CVE(s)), "
            f"policy={override_action.value.upper() if override_action else 'AUTO'}, "
            f"horizon={horizon}, blast_cap={blast_cap:.0f}, delay={delay_sec}s, "
            f"targets={[t.__name__ for t in targets]}: {', '.join(cve_queue)}"
        )

        def autonomous_worker() -> None:
            try:
                while not self._stop_auto.is_set():
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
                            trace.add(
                                "CVE Ingestion",
                                f"Failed to load {target_cve}: {err_msg}",
                            )
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
                                (
                                    "log",
                                    f"[AI Auto {run_id}] {target_cve} ERROR: {err_msg}",
                                )
                            )
                            continue

                        effective_delay = (
                            max(delay_sec, 6.0)
                            if (not was_cached and not self.client.api_key)
                            else delay_sec
                        )
                        if effective_delay > 0 and idx + 1 < len(current_queue):
                            steps = int(effective_delay * 10)
                            for _ in range(steps):
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
                            min_confidence=min_conf,
                            max_blast_radius=blast_cap,
                            harden_mutations=harden_mut,
                            auto_heal=auto_heal,
                            auto_witness=auto_witness,
                            auto_regret=auto_regret,
                            forecast_horizon=horizon,
                        )
                        matches = controller.check_targets(
                            *targets, trace=trace
                        )
                        self.events.put(("matches", matches))

                        installed_total = 0
                        actions_applied: list[str] = []
                        if allow_auto_apply:
                            for match in matches:
                                if self._stop_auto.is_set():
                                    break
                                if override_action is not None:
                                    chosen_action = override_action
                                    trace.add(
                                        "Policy Override",
                                        f"Using operator-selected policy={chosen_action.value.upper()} "
                                        f"for {match.flaw.flaw_id} on {match.target_name}.",
                                    )
                                else:
                                    chosen_action, _score = (
                                        controller.choose_action_with_reasoning(
                                            match, trace=trace
                                        )
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
                        if installed_total > 0 and auto_verify:
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
            messagebox.showwarning(
                "CVE required", "Enter at least one CVE ID first."
            )
            return
        self._set_busy(True, f"Loading {len(cve_queue)} CVE(s)…")
        self._log(
            f"Loading {', '.join(cve_queue)} "
            f"{'from NVD' if force else 'from cache/NVD'}."
        )

        def worker() -> None:
            try:
                for idx, cve_id in enumerate(cve_queue):
                    record = self.client.to_flaw_record(
                        cve_id, force_download=force
                    )
                    self.events.put(("record", record))
                    if (
                        force
                        and not self.client.api_key
                        and idx + 1 < len(cve_queue)
                    ):
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
            self.match_text.insert(
                "end", "No test-bench matches were reported.\n"
            )
            return
        for match in matches:
            w = weight_store.get_weight(
                match.flaw.flaw_id, match.target_name, match.flaw.probe_name
            )
            res = mutation_lattice.get_resilience(
                match.flaw.flaw_id, match.target_name
            )
            b_sc = boundary_engine.get_boundary_score(
                match.flaw.flaw_id, match.target_name
            )
            e_cert = epistemic_cartographer.get_certainty(
                match.flaw.flaw_id, match.target_name
            )
            w_press = witness_engine.get_evasion_pressure(
                match.flaw.flaw_id, match.target_name
            )
            br_entry = blast_regret_engine.get_entry(
                match.flaw.flaw_id, match.target_name
            )
            br_sc = (
                float(br_entry.get("selected_blast", 25.0))
                if isinstance(br_entry, dict)
                else 25.0
            )
            self.match_text.insert(
                "end",
                f"{match.flaw.flaw_id} → {match.target_name} "
                f"[weight={w:.2f}, resilience={res:.0%}, boundary={b_sc:.1f}, "
                f"epistemic={e_cert:.1f}, witness_pressure={w_press:.1f}, blast={br_sc:.1f}]\n"
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
                    self.refresh_evolution_view()
                    self.refresh_causal_forecast_view()
                    self.refresh_mutation_view()
                    self.refresh_boundary_view()
                    self.refresh_epistemic_view()
                    self.refresh_witness_view()
                    self.refresh_blast_view()
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
                    self._verify_guards_silently(
                        reinforce_matches=bool(self.auto_tune_var.get())
                    )
                    self.refresh_events_view()
                    self.refresh_reasoning_view()
                    self.refresh_causal_forecast_view()
                    self.refresh_mutation_view()
                    self.refresh_boundary_view()
                    self.refresh_epistemic_view()
                    self.refresh_witness_view()
                    self.refresh_blast_view()
                    self.run_counterfactual_and_diagnostics()
                elif kind == "busy_done":
                    self._set_busy(False, "Idle")
                elif kind == "auto_done":
                    self._auto_running = False
                    self._stop_auto.clear()
                    self.ai_auto_btn.configure(
                        text="AI Automatic", state="normal"
                    )
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
                values=(
                    record.severity.value.upper(),
                    record.probe_name,
                    record.title,
                ),
            )

    def _show_selected(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        record = next(
            (x for x in self.catalog if x.flaw_id == selected[0]), None
        )
        if record:
            self._display_record(record)
            self.refresh_evolution_view()
            self.refresh_causal_forecast_view()
            self.refresh_mutation_view()
            self.refresh_boundary_view()
            self.refresh_epistemic_view()
            self.refresh_witness_view()
            self.refresh_blast_view()

    def _display_record(self, record: FlawRecord) -> None:
        evolution = evolution_memory.prediction(record)
        text = (
            f"{record.flaw_id}\n"
            f"Severity: {record.severity.value.upper()}\n"
            f"Suggested check: {record.probe_name}\n"
            f"Suggested pattern: "
            f"{record.block_pattern or 'No automatic pattern — manual review required'}\n"
            f"Title: {record.title}\n\n"
            f"Description:\n{record.description}\n\n"
            f"NVD reference: {record.source_url or 'Not supplied'}\n\n"
            f"Evolution Memory: family={evolution['family']}; trend={evolution['trend']}; "
            f"raw priority={evolution['priority_score']}/100; "
            f"conf-weighted={evolution['confidence_weighted_score']}/100 "
            f"(confidence={evolution['confidence']:.0%}); "
            f"prior observations={evolution['pattern_count']}; "
            f"defense feedback worked={evolution['worked']} / failed={evolution['failed']}.\n\n"
            "Note: Validate affected product versions and configurations on your test bench. "
            "Evolution scores prioritize investigation; they are not proof of host exposure."
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
        self._log(
            f"Exported {len(serializable)} batch outcome(s) to {file_path}."
        )

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
        controller = self._build_controller(self.catalog)
        matches = controller.check_targets(
            *self._scoped_targets(), trace=trace
        )
        for rec in self.catalog:
            for t in self._scoped_targets():
                w = weight_store.get_weight(
                    rec.flaw_id, t.__name__, rec.probe_name
                )
                lat = MutationLatticeEngine.evaluate_lattice(
                    rec, t.__name__, registry.rules_for(t.__name__), persist=True
                )
                BoundaryGrammarEngine.verify_boundaries(
                    rec, t.__name__, registry.rules_for(t.__name__), persist=True
                )
                EpistemicCartographer.map_epistemic_space(
                    rec,
                    t.__name__,
                    registry.rules_for(t.__name__),
                    learned_weight=w,
                    persist=True,
                )
                w_syn = InvariantWitnessEngine.synthesize_witness(
                    rec,
                    t.__name__,
                    registry.rules_for(t.__name__),
                    learned_weight=w,
                    persist=bool(self.auto_witness_var.get()),
                )
                BlastRadiusRegretEngine.evaluate_regret(
                    rec,
                    t.__name__,
                    registry.rules_for(t.__name__),
                    learned_weight=w,
                    resilience_ratio=lat["resilience_ratio"],
                    witness_pressure=w_syn["evasion_pressure"],
                    persist=bool(self.auto_regret_var.get()),
                )
        trace.final_decision = f"Identified {len(matches)} bench match(es)."
        self._record_trace(trace)
        self._render_matches(matches)
        self.refresh_mutation_view()
        self.refresh_boundary_view()
        self.refresh_epistemic_view()
        self.refresh_witness_view()
        self.refresh_blast_view()
        self._log(
            f"Test-bench checks completed [{run_id}]: {len(matches)} match(es)."
        )

    def install_guards(self, action: GuardAction = GuardAction.BLOCK) -> None:
        if not self.last_matches:
            messagebox.showinfo(
                "Run checks first",
                "Run bench checks before installing guards.",
            )
            return
        run_id = self._next_run_id()
        cve_label = ", ".join(
            sorted({m.flaw.flaw_id for m in self.last_matches})
        )
        trace = ReasoningTrace(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            cve_id=cve_label,
            mode=f"Install {action.value.upper()}",
        )
        count = self._build_controller(self.catalog).apply_guards(
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
        if bool(self.auto_verify_var.get()):
            self._verify_guards_silently(
                reinforce_matches=bool(self.auto_tune_var.get())
            )
        self.refresh_events_view()
        self.refresh_causal_forecast_view()
        self.refresh_mutation_view()
        self.refresh_boundary_view()
        self.refresh_epistemic_view()
        self.refresh_witness_view()
        self.refresh_blast_view()
        self.run_counterfactual_and_diagnostics()
        messagebox.showinfo(
            "Guards installed",
            f"Installed {count} {action.value.upper()} rule(s).",
        )

    def _auto_rollback_if_enabled(self, reason: str) -> None:
        if not bool(self.auto_rollback_var.get()):
            return
        cps = rollback_ledger.checkpoints()
        if len(cps) < 2:
            return
        prior = cps[-2]
        registry.restore_rule_specs(prior.rule_specs)
        weight_store.restore_snapshot(prior.weights_snapshot)
        rollback_ledger.record_checkpoint(
            label=f"Auto-rollback ({reason}) -> {prior.checkpoint_id}",
            weights_snapshot=weight_store.snapshot(),
            rule_specs=registry.export_rule_specs(),
        )
        self._log(
            f"Auto-rollback triggered ({reason}): restored {prior.checkpoint_id}."
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
            tokens = parse_bench_command_tokens(
                "status --check; verify_token"
            )
            outcomes.append(f"parse_bench_command_tokens -> {tokens}")
        except GuardBlockedError as exc:
            cmd_intercepted = True
            self._log(str(exc))
            outcomes.append(str(exc))

        if self.last_matches:
            for match in self.last_matches:
                intercepted = (
                    path_intercepted
                    if match.target_name == "resolve_bench_path"
                    else cmd_intercepted
                )
                rules = registry.rules_for(match.target_name)
                act = rules[0].action.value if rules else "block"
                causal_info = causal_drift.record_intervention(
                    flaw_id=match.flaw.flaw_id,
                    target_name=match.target_name,
                    action=act,
                    pre_matched=True,
                    counterfactual_hit_rate=0.67,
                    post_verified_intercepted=intercepted,
                    note="Post-fix verification check",
                )
                lat = MutationLatticeEngine.evaluate_lattice(
                    match.flaw, match.target_name, rules, persist=True
                )
                BoundaryGrammarEngine.verify_boundaries(
                    match.flaw, match.target_name, rules, persist=True
                )
                w = weight_store.get_weight(
                    match.flaw.flaw_id, match.target_name, match.flaw.probe_name
                )
                EpistemicCartographer.map_epistemic_space(
                    match.flaw,
                    match.target_name,
                    rules,
                    learned_weight=w,
                    persist=True,
                )
                w_syn = InvariantWitnessEngine.synthesize_witness(
                    match.flaw,
                    match.target_name,
                    rules,
                    learned_weight=w,
                    persist=bool(self.auto_witness_var.get()),
                )
                BlastRadiusRegretEngine.evaluate_regret(
                    match.flaw,
                    match.target_name,
                    rules,
                    learned_weight=w,
                    resilience_ratio=lat["resilience_ratio"],
                    witness_pressure=w_syn["evasion_pressure"],
                    persist=bool(self.auto_regret_var.get()),
                )
                if causal_info["last_drift_score"] >= 0.50:
                    self._log(
                        f"Causal Drift Alert: {match.flaw.flaw_id} on {match.target_name} "
                        f"drift_score={causal_info['last_drift_score']:.2f}"
                    )
                    self._auto_rollback_if_enabled(
                        f"drift={causal_info['last_drift_score']:.2f}"
                    )
                elif lat["resilience_ratio"] < 0.25 and act == "block":
                    self._auto_rollback_if_enabled(
                        f"low_resilience={lat['resilience_ratio']:.0%}"
                    )
                if reinforce_matches and intercepted:
                    weight_store.update_weight(
                        match.flaw.flaw_id,
                        match.target_name,
                        match.flaw.probe_name,
                        +0.10,
                        "Guard verified active during post-fix check",
                    )
        return outcomes

    def verify_guards(self) -> None:
        outcomes = self._verify_guards_silently(
            reinforce_matches=bool(self.auto_tune_var.get())
        )
        self.refresh_events_view()
        self.refresh_reasoning_view()
        self.refresh_causal_forecast_view()
        self.refresh_mutation_view()
        self.refresh_boundary_view()
        self.refresh_epistemic_view()
        self.refresh_witness_view()
        self.refresh_blast_view()
        messagebox.showinfo("Guard verification", "\n".join(outcomes))

    def run_mutation_lattice_scan(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        targets = [t.__name__ for t in self._scoped_targets()]
        for rec in self.catalog:
            for tname in targets:
                MutationLatticeEngine.evaluate_lattice(
                    rec, tname, registry.rules_for(tname), persist=True
                )
        self.refresh_mutation_view()
        self._log(
            f"Completed mutation lattice scan across {len(self.catalog)} CVE(s) and {len(targets)} target(s)."
        )

    def refresh_mutation_view(self) -> None:
        if not hasattr(self, "mutation_text"):
            return
        self.mutation_text.delete("1.0", "end")
        self.mutation_text.insert("end", mutation_lattice.report() + "\n")

    def run_boundary_grammar_scan(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        targets = [t.__name__ for t in self._scoped_targets()]
        for rec in self.catalog:
            for tname in targets:
                BoundaryGrammarEngine.verify_boundaries(
                    rec, tname, registry.rules_for(tname), persist=True
                )
        self.refresh_boundary_view()
        self._log(
            f"Completed boundary & grammar verification across {len(self.catalog)} CVE(s) and {len(targets)} target(s)."
        )

    def refresh_boundary_view(self) -> None:
        if not hasattr(self, "boundary_text"):
            return
        self.boundary_text.delete("1.0", "end")
        self.boundary_text.insert("end", boundary_engine.report() + "\n")

    def run_epistemic_cartography(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        targets = [t.__name__ for t in self._scoped_targets()]
        for rec in self.catalog:
            for tname in targets:
                w = weight_store.get_weight(
                    rec.flaw_id, tname, rec.probe_name
                )
                EpistemicCartographer.map_epistemic_space(
                    rec,
                    tname,
                    registry.rules_for(tname),
                    learned_weight=w,
                    persist=True,
                )
        self.refresh_epistemic_view()
        self._log(
            f"Completed epistemic cartography across {len(self.catalog)} CVE(s) and {len(targets)} target(s)."
        )

    def refresh_epistemic_view(self) -> None:
        if not hasattr(self, "epistemic_text"):
            return
        self.epistemic_text.delete("1.0", "end")
        self.epistemic_text.insert(
            "end", epistemic_cartographer.report() + "\n"
        )

    def run_witness_synthesis(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        targets = [t.__name__ for t in self._scoped_targets()]
        for rec in self.catalog:
            for tname in targets:
                w = weight_store.get_weight(
                    rec.flaw_id, tname, rec.probe_name
                )
                InvariantWitnessEngine.synthesize_witness(
                    rec,
                    tname,
                    registry.rules_for(tname),
                    learned_weight=w,
                    persist=True,
                )
        self.refresh_witness_view()
        self._log(
            f"Synthesized counterexample witnesses across {len(self.catalog)} CVE(s) and {len(targets)} target(s)."
        )

    def refresh_witness_view(self) -> None:
        if not hasattr(self, "witness_text"):
            return
        self.witness_text.delete("1.0", "end")
        self.witness_text.insert("end", witness_engine.report() + "\n")

    def run_blast_regret_scan(self) -> None:
        if not self.catalog:
            messagebox.showinfo("No CVEs", "Fetch at least one CVE first.")
            return
        targets = [t.__name__ for t in self._scoped_targets()]
        for rec in self.catalog:
            for tname in targets:
                w = weight_store.get_weight(
                    rec.flaw_id, tname, rec.probe_name
                )
                res = mutation_lattice.get_resilience(rec.flaw_id, tname)
                w_press = witness_engine.get_evasion_pressure(
                    rec.flaw_id, tname
                )
                BlastRadiusRegretEngine.evaluate_regret(
                    rec,
                    tname,
                    registry.rules_for(tname),
                    learned_weight=w,
                    resilience_ratio=res,
                    witness_pressure=w_press,
                    persist=True,
                )
        self.refresh_blast_view()
        self._log(
            f"Evaluated blast radius & regret across {len(self.catalog)} CVE(s) and {len(targets)} target(s)."
        )

    def refresh_blast_view(self) -> None:
        if not hasattr(self, "blast_text"):
            return
        self.blast_text.delete("1.0", "end")
        self.blast_text.insert("end", blast_regret_engine.report() + "\n")

    def refresh_causal_forecast_view(self) -> None:
        if not hasattr(self, "causal_text"):
            return
        self.causal_text.delete("1.0", "end")
        record = self._selected_flaw_record()
        drift_alerts = causal_drift.drift_alerts()

        if record:
            tname = (
                "resolve_bench_path"
                if record.probe_name == "check_path_resolution"
                else "parse_bench_command_tokens"
            )
            w = weight_store.get_weight(
                record.flaw_id, tname, record.probe_name
            )
            res = mutation_lattice.get_resilience(record.flaw_id, tname)
            e_cert = epistemic_cartographer.get_certainty(
                record.flaw_id, tname
            )
            w_press = witness_engine.get_evasion_pressure(
                record.flaw_id, tname
            )
            br_entry = blast_regret_engine.get_entry(record.flaw_id, tname)
            br_press = (
                float(br_entry.get("selected_blast", 25.0))
                if isinstance(br_entry, dict)
                else 25.0
            )
            mem = evolution_memory.prediction(record)
            fc = PredictiveForecastEngine.forecast(
                record,
                w,
                mem,
                drift_alerts,
                res,
                e_cert,
                w_press,
                blast_pressure=br_press,
                horizon=self._horizon(),
            )
            self.causal_text.insert(
                "end",
                f"=== PREDICTIVE FORECAST ({record.flaw_id} | {fc['horizon']}) ===\n",
            )
            for line in fc["rationale"]:
                self.causal_text.insert("end", f"  • {line}\n")
            self.causal_text.insert("end", "\n")

        self.causal_text.insert("end", causal_drift.summary_report() + "\n")

    def run_counterfactual_and_diagnostics(self) -> None:
        self.ledger_text.delete("1.0", "end")
        ok, chain_msg = rollback_ledger.verify_integrity()
        self.ledger_text.insert(
            "end", f"=== Hash-Chain Integrity ===\n{chain_msg}\n\n"
        )

        self.ledger_text.insert("end", "=== Checkpoints ===\n")
        cps = rollback_ledger.checkpoints()
        if not cps:
            self.ledger_text.insert(
                "end", "No ledger checkpoints recorded yet.\n\n"
            )
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

        self.ledger_text.insert(
            "end", "=== Rule Diagnostics (Overlap & Bypass Vectors) ===\n"
        )
        any_diag = False
        for tname in ("resolve_bench_path", "parse_bench_command_tokens"):
            diags = RuleDiagnostics.analyze_target(
                tname, registry.rules_for(tname)
            )
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
            messagebox.showwarning(
                "Not found", f"Checkpoint '{cp_id}' not found."
            )
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

    def _selected_flaw_record(self) -> Optional[FlawRecord]:
        selected = self.tree.selection() if hasattr(self, "tree") else ()
        selected_id = selected[0] if selected else None
        if selected_id:
            return next(
                (item for item in self.catalog if item.flaw_id == selected_id),
                None,
            )
        return self.catalog[-1] if self.catalog else None

    def _refresh_evolution_history_tree(self) -> None:
        if not hasattr(self, "evolution_history_tree"):
            return
        for item in self.evolution_history_tree.get_children():
            self.evolution_history_tree.delete(item)
        snap = evolution_memory.export_snapshot()
        cve_hist = snap.get("cve_history") or {}
        ordered = sorted(
            cve_hist.values(),
            key=lambda x: (int(x.get("observations", 0)), x.get("last_seen", "")),
            reverse=True,
        )
        for rec in ordered:
            cve_id = rec.get("cve_id", "")
            fam = rec.get("family", "UNCLASSIFIED")
            obs = int(rec.get("observations", 0))
            sevs = ", ".join(rec.get("severities") or [])
            stats = ", ".join(rec.get("statuses") or [])
            hist = rec.get("history") or []
            if obs >= 2 and len(hist) >= 2:
                comp = (
                    f"Recurring (x{obs}): {hist[0].get('severity')}->{hist[-1].get('severity')}, "
                    f"{hist[0].get('status')}->{hist[-1].get('status')}"
                )
            else:
                comp = f"Single observation ({hist[-1].get('summary', '')[:70] if hist else ''})"
            self.evolution_history_tree.insert(
                "",
                "end",
                iid=f"hist_{cve_id}",
                values=(cve_id, fam, obs, sevs, stats, comp),
            )

    def refresh_evolution_view(self) -> None:
        if not hasattr(self, "evolution_text"):
            return
        self._refresh_evolution_history_tree()
        self.evolution_text.delete("1.0", "end")

        alerts = evolution_memory.failure_alerts()
        if alerts:
            self.evolution_text.insert(
                "end", "=== ACTIVE DEFENSE FAILURE-PATTERN ALERTS ===\n"
            )
            for a in alerts:
                self.evolution_text.insert("end", f"  {a['message']}\n")
            self.evolution_text.insert("end", "\n")

        record = self._selected_flaw_record()
        if record:
            insight = evolution_memory.prediction(record)
            self.evolution_text.insert(
                "end", "=== CONFIDENCE-WEIGHTED PREDICTION & EXPLANATION ===\n"
            )
            self.evolution_text.insert(
                "end",
                f"{record.flaw_id} | family={insight['family']} | trend={insight['trend']} | "
                f"conf-weighted={insight['confidence_weighted_score']}/100 "
                f"(raw={insight['priority_score']}/100, confidence={insight['confidence']:.0%})\n",
            )
            for reason in insight["reasons"]:
                self.evolution_text.insert("end", f" • {reason}\n")
            self.evolution_text.insert("end", "\n")

        self.evolution_text.insert("end", evolution_memory.report())

    def record_evolution_feedback(self, worked: bool) -> None:
        record = self._selected_flaw_record()
        if record is None:
            messagebox.showinfo(
                "Select a CVE",
                "Fetch and select a CVE in the catalog first.",
            )
            return
        action = self.evolution_action_var.get().strip().upper() or "OTHER"
        try:
            result = evolution_memory.record_defense_feedback(
                record,
                action,
                worked,
                notes="Operator-confirmed feedback recorded in Evolution Memory UI.",
            )
        except OSError as exc:
            messagebox.showerror("Memory save failed", str(exc))
            return
        label = "WORKED" if worked else "FAILED"
        self._log(
            f"Evolution Memory: recorded {action} {label} for {record.flaw_id} ({result['family']})."
        )
        for alert in evolution_memory.failure_alerts(family=result["family"]):
            self._log(f"Defense Failure Alert: {alert['message']}")
        self.refresh_evolution_view()
        self.refresh_reasoning_view()

    def export_evolution_memory(self) -> None:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="vulnerability_evolution_memory.json",
        )
        if not file_path:
            return
        try:
            atomic_write_json(
                Path(file_path), evolution_memory.export_snapshot()
            )
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._log(f"Exported Vulnerability Evolution Memory to {file_path}.")

    def refresh_reasoning_view(self) -> None:
        self.reasoning_text.delete("1.0", "end")
        weights_snap = weight_store.snapshot()
        self.reasoning_text.insert("end", "=== Learned Weights ===\n")
        if not weights_snap:
            self.reasoning_text.insert(
                "end", "No learned weights recorded yet.\n\n"
            )
        else:
            for key, info in weights_snap.items():
                self.reasoning_text.insert(
                    "end",
                    f"  {key}: weight={info.get('weight', 1.0):.4f} "
                    f"(samples={info.get('samples', 0)}) — {info.get('last_reason', '')}\n",
                )
            self.reasoning_text.insert("end", "\n")

        self.reasoning_text.insert(
            "end", "=== Evolution Memory Signal ===\n"
        )
        selected_record = self._selected_flaw_record()
        if selected_record:
            mem = evolution_memory.prediction(selected_record)
            self.reasoning_text.insert(
                "end",
                f"{selected_record.flaw_id}: family={mem['family']}, trend={mem['trend']}, "
                f"conf-weighted={mem['confidence_weighted_score']}/100 "
                f"(raw={mem['priority_score']}/100, conf={mem['confidence']:.0%}), "
                f"novelty={mem['novel']}, defense worked={mem['worked']}, failed={mem['failed']}.\n\n",
            )
        else:
            self.reasoning_text.insert(
                "end", "Load a CVE to see its evolution signal.\n\n"
            )

        self.reasoning_text.insert(
            "end", "=== Explainable Reasoning Traces ===\n\n"
        )
        if not self.traces:
            self.reasoning_text.insert(
                "end", "No reasoning traces recorded yet.\n"
            )
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