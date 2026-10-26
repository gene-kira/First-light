#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BORG AI AdDefender — Predictive Adaptive Edition
Version 10.3

Athelas-inspired learning agent, explainable review recommendations, feedback audits, predictive risk trends, Defender Units, LAN proxy, local network device scanner, signal-flow forecasting, integrity watchdog, and observation mesh.
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import html
import webbrowser
import uuid
from dataclasses import dataclass, field
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "BORG AI AdDefender"
APP_VERSION = "10.3"
IS_WINDOWS = os.name == "nt"


def ensure_admin() -> None:
    """Relaunch on Windows with UAC elevation before touching protected resources.

    Returns normally only when already elevated or when running on a non-Windows
    platform. If a replacement process is launched, the current process exits.
    """
    if not IS_WINDOWS:
        return

    try:
        if bool(ctypes.windll.shell32.IsUserAnAdmin()):
            print(f"[{APP_NAME}] Elevation check passed.")
            return

        script = os.path.abspath(sys.argv[0])
        # Correctly quote script path and every argument, including spaces.
        params = subprocess.list2cmdline([script, *sys.argv[1:]])
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(Path(script).parent),
            1,
        )

        # ShellExecuteW returns a value > 32 when launch succeeds.
        if result > 32:
            print(f"[{APP_NAME}] UAC elevation requested; exiting this process.")
            raise SystemExit(0)

        message = (
            f"[{APP_NAME}] Could not relaunch with administrator privileges "
            f"(ShellExecuteW result: {result}).\n\n"
            "Please restart the application and approve the Windows UAC prompt."
        )
        print(message, file=sys.stderr)
        try:
            ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)
        except Exception:
            pass
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        message = f"[{APP_NAME}] Elevation failed: {exc}"
        print(message, file=sys.stderr)
        try:
            ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)
        except Exception:
            pass
        raise SystemExit(1)
BASE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "BORGAdDefender" if IS_WINDOWS else Path.home() / ".borg_addefender"
HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts" if IS_WINDOWS else Path("/etc/hosts")
CONFIG_PATH = BASE_DIR / "config.json"
MODEL_PATH = BASE_DIR / "online_model.json"
REPUTATION_PATH = BASE_DIR / "domain_reputation.json"
KNOWLEDGE_PATH = BASE_DIR / "borg_knowledge.json"
AGENT_STATE_PATH = BASE_DIR / "agent_state.json"
AGENT_AUDIT_PATH = BASE_DIR / "agent_audit.jsonl"
EVENTS_PATH = BASE_DIR / "events.jsonl"
BACKUP_DIR = BASE_DIR / "backups"
RULE_DIR = BASE_DIR / "rules"
PLUGIN_DIR = BASE_DIR / "plugins"
PAYLOAD_DIR = BASE_DIR / "payloads"
DEFENDER_DIR = BASE_DIR / "defenders"

DEFAULT_CONFIG = {
    "monitor_interval": 2.0,
    "rules_sync_interval": 21600,
    "drone_enabled": False,
    "auto_block_enabled": False,
    "auto_block_threshold": 0.94,
    "minimum_evidence": 8,
    "require_rule_or_feedback": True,
    "max_domains": 3000,
    "max_events": 5000,
    "lan_proxy_enabled": False,
    "lan_proxy_port": 8081,
    "lan_proxy_bind": "127.0.0.1",
    "prediction_window_seconds": 120,
    "trend_history_points": 10,
    "trend_adjustment_cap": 0.08,
    "proxy_max_response_bytes": 5000000,
    "burst_observation_threshold": 6,
    "learning_rate": 0.04,
    "max_payload_bytes": 2000000,
    "local_network_scan_cidr": "",  # optional override, else ARP-based
    "agent_enabled": True,
    "agent_interval_seconds": 60,
    "agent_max_recommendations": 20,
    "agent_high_risk_threshold": 0.82,
    "agent_false_positive_threshold": 0.70,
    "signal_history_points": 20,
    "mesh_max_nodes": 2000,
    "mesh_max_edges": 5000,
}

RULE_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
]
USER_AGENT = f"{APP_NAME}/{APP_VERSION}"
DOMAIN_RE = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$", re.I)
AD_TERMS = (
    "doubleclick", "googlesyndication", "googleadservices", "adservice",
    "adserver", "adsystem", "adnxs", "adform", "advertising", "adtech",
    "adroll", "outbrain", "taboola", "criteo", "pubmatic", "openx",
    "rubiconproject", "amazon-adsystem", "adsrvr", "smartadserver",
    "moatads", "serving-sys", "prebid", "adsbygoogle", "adzerk",
)
TRACKING_TERMS = (
    "pixel", "beacon", "tracker", "tracking", "analytics", "telemetry",
    "metrics", "measurement", "fingerprint", "segment.io", "mixpanel",
    "hotjar", "newrelic", "scorecardresearch", "quantserve",
)
VIDEO_TERMS = ("vast", "vpaid", "videoad", "video-ad", "imasdk")
CDN_TERMS = ("cloudfront.net", "akamai", "fastly.net", "cloudflare")
SAFE_BUILTINS = {"localhost", "localhost.localdomain", "broadcasthost"}

def now_ts() -> float:
    return time.time()

def iso_time(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or now_ts()).astimezone().strftime("%Y-%m-%d %H:%M:%S")

def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))

def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

class EventLog:
    def __init__(self):
        self.lock = threading.RLock()
        self.items = deque(maxlen=500)
        self.listeners = []

    def add_listener(self, fn):
        self.listeners.append(fn)

    def log(self, message: str, level: str = "INFO", **extra):
        row = {"ts": now_ts(), "time": iso_time(), "level": level, "message": str(message)[:1200]}
        row.update(extra)
        with self.lock:
            self.items.appendleft(row)
        try:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
            with EVENTS_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            pass
        for fn in tuple(self.listeners):
            try:
                fn(row)
            except Exception:
                pass

    def snapshot(self):
        with self.lock:
            return list(self.items)

LOG = EventLog()

def normalize_domain(value: str) -> str | None:
    if not value:
        return None
    value = str(value).strip().lower().rstrip(".")
    if "://" in value:
        try:
            value = urllib.parse.urlsplit(value).hostname or ""
        except Exception:
            return None
    value = value.split("/")[0].split(":")[0].strip().strip(".")
    if not value or len(value) > 253 or value in SAFE_BUILTINS:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except Exception:
        return None
    if not DOMAIN_RE.fullmatch(value):
        return None
    if value.endswith((".local", ".lan", ".internal", ".test", ".invalid")):
        return None
    return value

def domain_features(domain: str) -> dict[str, float]:
    d = domain.lower()
    labels = d.split(".")
    ad = any(term in d for term in AD_TERMS)
    tracking = any(term in d for term in TRACKING_TERMS)
    video = any(term in d for term in VIDEO_TERMS)
    cdn = any(term in d for term in CDN_TERMS)
    numeric_label = any(label.isdigit() for label in labels)
    long_host = len(d) > 42
    many_labels = len(labels) >= 4
    return {
        "ad_token": float(ad),
        "tracking_token": float(tracking),
        "video_token": float(video),
        "cdn_token": float(cdn),
        "numeric_label": float(numeric_label),
        "long_host": float(long_host),
        "many_labels": float(many_labels),
        "subdomain_depth": min(1.0, max(0, len(labels) - 2) / 5.0),
    }

def family_for(domain: str) -> str:
    f = domain_features(domain)
    if f["video_token"]:
        return "video-ad candidate"
    if f["ad_token"]:
        return "ad-network candidate"
    if f["tracking_token"]:
        return "tracking candidate"
    if f["cdn_token"]:
        return "CDN / shared infrastructure"
    return "unknown"

class OnlineLogisticModel:
    def __init__(self):
        self.lock = threading.RLock()
        saved = read_json(MODEL_PATH, {})
        self.weights = {k: float(v) for k, v in saved.get("weights", {}).items()}
        self.bias = float(saved.get("bias", -2.2))
        self.examples = int(saved.get("examples", 0))
        self.positives = int(saved.get("positives", 0))
        self.negatives = int(saved.get("negatives", 0))
        self.correct = int(saved.get("correct", 0))
        self.evaluated = int(saved.get("evaluated", 0))
        self.learning_rate = clamp(float(saved.get("learning_rate", 0.04)), 0.001, 0.1)

    def probability(self, features: dict[str, float]) -> float:
        with self.lock:
            z = self.bias + sum(self.weights.get(k, 0.0) * v for k, v in features.items())
        z = max(-20.0, min(20.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def learn(self, features: dict[str, float], label: int):
        y = 1 if label else 0
        with self.lock:
            z = self.bias + sum(self.weights.get(k, 0.0) * v for k, v in features.items())
            p = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
            self.evaluated += 1
            if (p >= 0.5) == bool(y):
                self.correct += 1
            err = p - y
            for k, v in features.items():
                old = self.weights.get(k, 0.0)
                self.weights[k] = old - self.learning_rate * (err * v + 0.002 * old)
            self.bias -= self.learning_rate * err
            self.examples += 1
            self.positives += y
            self.negatives += 1 - y
        self.save()
        return p

    def save(self):
        with self.lock:
            data = {
                "weights": self.weights, "bias": self.bias, "examples": self.examples,
                "positives": self.positives, "negatives": self.negatives,
                "correct": self.correct, "evaluated": self.evaluated,
                "updated_at": now_ts(), "learning_rate": self.learning_rate,
            }
        try:
            atomic_json(MODEL_PATH, data)
        except Exception as e:
            LOG.log(f"Could not save learning model: {e}", "ERROR")

    def metrics(self):
        with self.lock:
            return {
                "examples": self.examples, "positives": self.positives,
                "negatives": self.negatives,
                "accuracy": self.correct / self.evaluated if self.evaluated else None,
                "weights": dict(self.weights), "bias": self.bias,
            }

class DefenderUnit:
    def __init__(self, domain: str, family: str, score: float, payload_path: Path | None, analysis: dict[str, Any]):
        self.domain = domain
        self.family = family
        self.score = score
        self.payload_path = payload_path
        self.analysis = analysis
        self.created_at = iso_time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "family": self.family,
            "score": self.score,
            "payload_path": str(self.payload_path) if self.payload_path else None,
            "analysis": self.analysis,
            "created_at": self.created_at,
        }

    def render_html(self) -> str:
        trackers = self.analysis.get("trackers", [])
        scripts = self.analysis.get("scripts", [])
        endpoints = self.analysis.get("endpoints", [])
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>BORG AdDefender</title>"
            "<style>"
            "body{font-family:Segoe UI,system-ui,sans-serif;background:#111;color:#eee;padding:12px;}"
            ".box{border:1px solid #444;border-radius:6px;padding:10px;background:#1b1b1b;}"
            ".tag{display:inline-block;margin:2px 4px;padding:2px 6px;border-radius:4px;background:#333;font-size:11px;}"
            "</style></head><body>"
            "<div class='box'>"
            f"<h2>Ad Defender Shield: {html.escape(self.domain)}</h2>"
            f"<p>Family: <b>{html.escape(self.family)}</b> &nbsp; | &nbsp; Score: <b>{self.score:.3f}</b></p>"
            "<p>This is a static risk summary for the domain. It does not prove content was intercepted or neutralized.</p>"
            "<h3>Detected trackers / tokens</h3>"
            + "".join(f"<span class='tag'>{html.escape(str(t))}</span>" for t in trackers or ["none detected"])
            + "<h3>Script patterns</h3>"
            + "".join(f"<span class='tag'>{html.escape(str(s))}</span>" for s in scripts or ["none detected"])
            + "<h3>Network endpoints</h3>"
            + "".join(f"<span class='tag'>{html.escape(str(e))}</span>" for e in endpoints or ["none detected"])
            + "<p style='margin-top:10px;font-size:11px;color:#aaa;'>"
            "This Defender Unit is a static explanation. No remote code or tracking is executed."
            "</p>"
            "</div></body></html>"
        )

class AdAnalyzer:
    def __init__(self):
        PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
        DEFENDER_DIR.mkdir(parents=True, exist_ok=True)

    def fetch_payload(self, url: str, domain: str) -> Path | None:
        """Fetch a small, same-domain sample for static analysis only."""
        if requests is None:
            return None
        try:
            parsed = urllib.parse.urlsplit(url)
            host = normalize_domain(parsed.hostname or "")
            expected = normalize_domain(domain)
            if parsed.scheme not in ("http", "https") or not host or not expected:
                LOG.log("Payload fetch refused: invalid URL or scheme.", "WARN")
                return None
            if host != expected and not host.endswith("." + expected):
                LOG.log("Payload fetch refused: URL host does not match analyzed domain.", "WARN")
                return None
            r = requests.get(url, timeout=(5, 10), headers={"User-Agent": USER_AGENT},
                             stream=True, allow_redirects=False)
            r.raise_for_status()
            limit = 2_000_000
            chunks, total = [], 0
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit:
                    LOG.log(f"Payload fetch capped at {limit} bytes for {domain}.", "WARN")
                    break
                chunks.append(chunk)
            content = b"".join(chunks).decode(r.encoding or "utf-8", errors="replace")
            fname = PAYLOAD_DIR / f"{expected}_{int(now_ts())}.html"
            fname.write_text(content, encoding="utf-8", errors="ignore")
            return fname
        except Exception as e:
            LOG.log(f"Payload fetch failed for {url}: {e}", "WARN")
            return None

    def analyze_payload(self, payload_path: Path | None, domain: str, family: str, score: float) -> DefenderUnit:
        analysis = {"trackers": [], "scripts": [], "endpoints": []}
        text = ""
        if payload_path and payload_path.exists():
            try:
                text = payload_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                text = ""
        if text:
            urls = re.findall(r"https?://[^\s\"'<>]+", text)
            analysis["endpoints"] = sorted(set(urls))[:50]
            tokens = []
            for term in AD_TERMS + TRACKING_TERMS + VIDEO_TERMS:
                if term in text.lower():
                    tokens.append(term)
            analysis["trackers"] = sorted(set(tokens))[:50]
            scripts = []
            for m in re.finditer(r"<script[^>]*>(.*?)</script>", text, flags=re.I | re.S):
                body = m.group(1)
                if "analytics" in body.lower() or "track" in body.lower() or "pixel" in body.lower():
                    scripts.append("tracking-like script")
            analysis["scripts"] = sorted(set(scripts))[:20]
        unit = DefenderUnit(domain, family, score, payload_path, analysis)
        try:
            out = DEFENDER_DIR / f"defender_{domain}_{int(now_ts())}.json"
            out.write_text(json.dumps(unit.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            LOG.log(f"Could not persist defender unit for {domain}: {e}", "WARN")
        return unit

class BorgLearningAgent:
    """Bounded, explainable review agent. It recommends; it never silently changes blocks."""
    def __init__(self):
        saved = read_json(AGENT_STATE_PATH, {})
        self.lock = threading.RLock()
        self.last_run = float(saved.get("last_run", 0) or 0)
        self.cycles = int(saved.get("cycles", 0) or 0)
        self.last_report = saved.get("last_report", {}) if isinstance(saved.get("last_report", {}), dict) else {}
        self.audit_limit = 500

    def _audit(self, event: dict[str, Any]):
        try:
            AGENT_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with AGENT_AUDIT_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"time": iso_time(), **event}, ensure_ascii=False) + "\n")
            # Bound audit file growth without deleting recent decision history.
            if AGENT_AUDIT_PATH.stat().st_size > 2_000_000:
                lines = AGENT_AUDIT_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()[-self.audit_limit:]
                AGENT_AUDIT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as e:
            LOG.log(f"Agent audit write failed: {e}", "WARN")

    def review(self, engine: "BorgEngine", force: bool = False) -> dict[str, Any]:
        now = now_ts()
        interval = max(10, int(engine.config.get("agent_interval_seconds", 60)))
        with self.lock:
            if not force and self.last_report and now - self.last_run < interval:
                return dict(self.last_report)
        recommendations = []
        labeled = 0
        false_positive_candidates = 0
        false_negative_candidates = 0
        with engine.lock:
            snapshot = [(d, dict(v)) for d, v in engine.domains.items()]
            allowlist, blocklist, rules = set(engine.allowlist), set(engine.blocklist), set(engine.rule_domains)
        high_risk = float(engine.config.get("agent_high_risk_threshold", 0.82))
        fp_threshold = float(engine.config.get("agent_false_positive_threshold", 0.70))
        for domain, stats in snapshot:
            label = stats.get("label")
            prob = engine.model.probability(domain_features(domain))
            obs = int(stats.get("observations", 0) or 0)
            rule_hit = any(".".join(domain.split(".")[i:]) in rules for i in range(len(domain.split(".")) - 1))
            if label is not None:
                labeled += 1
                if label == 0 and prob >= fp_threshold:
                    false_positive_candidates += 1
                    recommendations.append({"priority": 1, "domain": domain, "kind": "review_false_positive", "score": prob,
                        "reason": "Model still scores this user-confirmed legitimate domain highly; review its features and training balance."})
                elif label == 1 and prob <= (1.0 - high_risk):
                    false_negative_candidates += 1
                    recommendations.append({"priority": 1, "domain": domain, "kind": "review_false_negative", "score": prob,
                        "reason": "Model score conflicts with user-confirmed ad/tracker feedback; check for feature gaps."})
            elif domain not in allowlist and domain not in blocklist and (prob >= high_risk or rule_hit):
                recommendations.append({"priority": 2 if rule_hit else 3, "domain": domain, "kind": "review_candidate", "score": prob,
                    "reason": "Filter-list evidence" if rule_hit else f"Elevated model score with {obs} observations; verify before blocking."})
        recommendations.sort(key=lambda x: (x["priority"], -x["score"], x["domain"]))
        cap = max(1, min(100, int(engine.config.get("agent_max_recommendations", 20))))
        recommendations = recommendations[:cap]
        metrics = engine.model.metrics()
        report = {
            "generated_at": iso_time(now), "last_run": now, "cycles": self.cycles + 1,
            "domains_reviewed": len(snapshot), "labeled_domains": labeled,
            "false_positive_candidates": false_positive_candidates,
            "false_negative_candidates": false_negative_candidates,
            "training_examples": metrics["examples"], "online_accuracy_estimate": metrics["accuracy"],
            "recommendations": recommendations,
            "safety_note": "Recommendations only. Predictions do not prove a domain is malicious; the agent does not autonomously block domains or alter the hosts file.",
        }
        with self.lock:
            self.last_run = now
            self.cycles += 1
            self.last_report = report
            try:
                atomic_json(AGENT_STATE_PATH, {"last_run": self.last_run, "cycles": self.cycles, "last_report": report})
            except Exception as e:
                LOG.log(f"Agent state save failed: {e}", "WARN")
        self._audit({"action": "review_cycle", "domains_reviewed": len(snapshot), "recommendation_count": len(recommendations),
                     "false_positive_candidates": false_positive_candidates, "false_negative_candidates": false_negative_candidates})
        LOG.log(f"Learning agent review completed: {len(snapshot)} domains reviewed, {len(recommendations)} recommendations.")
        return report


@dataclass
class PromptTask:
    """One bounded task in the local self-prompting review workflow."""
    id: str
    description: str
    status: str = "pending"
    result: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptAgentState:
    goal: str
    tasks: list[PromptTask] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    prompt_profile: dict[str, Any] = field(default_factory=dict)
    step_count: int = 0


class SelfPromptingAgent:
    """Bounded self-prompting workflow integrated with BORG's local evidence.

    By default this agent uses local deterministic analysis and does not require an
    API key, internet access, or an LLM package. An optional llm_call callback can
    be injected by a developer, but is never configured or invoked automatically.
    It only produces analysis and recommendations; it cannot apply blocks or edit
    the hosts file.
    """
    def __init__(self, max_steps: int = 12, enable_prompt_optimization: bool = True,
                 llm_call: Optional[Callable[[str, str], str]] = None):
        self.max_steps = max(1, min(50, int(max_steps)))
        self.enable_prompt_optimization = bool(enable_prompt_optimization)
        self.llm_call = llm_call
        self.lock = threading.RLock()
        saved = read_json(AGENT_STATE_PATH, {})
        self.last_report = saved.get("self_prompting_report", {}) if isinstance(saved, dict) else {}
        self.prompt_profile = {"style": "technical", "verbosity": "medium"}

    def run(self, engine: "BorgEngine", goal: Optional[str] = None) -> dict[str, Any]:
        state = PromptAgentState(goal=(goal or "Review AdDefender evidence and recommend safe improvements."),
                                prompt_profile=dict(self.prompt_profile))
        self._initialize_tasks(state)
        while self._continue(state):
            self._run_step(state, engine)
        report = {
            "generated_at": iso_time(),
            "goal": state.goal,
            "mode": "optional-LLM" if self.llm_call else "local-evidence",
            "steps": state.step_count,
            "prompt_profile": state.prompt_profile,
            "tasks": [{"id": t.id, "description": t.description, "status": t.status,
                       "result": t.result, "meta": t.meta} for t in state.tasks],
            "history": state.history[-50:],
            "safety_note": "Analysis and recommendations only. This workflow does not automatically block domains, change allow/block lists, or modify the hosts file. Predictions require verification.",
        }
        with self.lock:
            self.last_report = report
            self.prompt_profile = dict(state.prompt_profile)
        try:
            saved = read_json(AGENT_STATE_PATH, {})
            if not isinstance(saved, dict):
                saved = {}
            saved["self_prompting_report"] = report
            saved["self_prompting_profile"] = self.prompt_profile
            atomic_json(AGENT_STATE_PATH, saved)
        except Exception as exc:
            LOG.log(f"Self-prompting state save failed: {exc}", "WARN")
        try:
            AGENT_AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with AGENT_AUDIT_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"time": iso_time(), "action": "self_prompting_run",
                                    "mode": report["mode"], "steps": report["steps"],
                                    "goal": report["goal"][:500]}, ensure_ascii=False) + "\n")
        except Exception:
            pass
        LOG.log(f"Self-prompting review completed: {report['steps']} steps ({report['mode']} mode).")
        return report

    def _initialize_tasks(self, state: PromptAgentState) -> None:
        # Small, bounded plan tailored to the actual data BORG already has.
        plan = [
            ("model_metrics", "Review model training balance and current metrics."),
            ("feedback_conflicts", "Find confirmed labels that conflict with model predictions."),
            ("list_consistency", "Check allowlist, blocklist, and rule evidence consistency."),
            ("coverage_gaps", "Identify observed domains that still lack explicit feedback."),
            ("safe_actions", "Prioritize safe, evidence-backed next steps."),
        ]
        state.tasks = [PromptTask(id=str(uuid.uuid4()), description=desc, meta={"kind": kind})
                       for kind, desc in plan]

    def _continue(self, state: PromptAgentState) -> bool:
        if state.step_count >= self.max_steps:
            return False
        return any(t.status == "pending" for t in state.tasks)

    def _run_step(self, state: PromptAgentState, engine: "BorgEngine") -> None:
        task = next((t for t in state.tasks if t.status == "pending"), None)
        if task is None:
            return
        state.step_count += 1
        try:
            task.result = self._execute_local_task(engine, task)
            task.status = "done"
        except Exception as exc:
            task.result = f"Task failed safely: {type(exc).__name__}: {exc}"
            task.status = "failed"
            LOG.log(f"Self-prompting task failed ({task.meta.get('kind')}): {exc}", "WARN")
        row = {"step": state.step_count, "task_id": task.id, "task_description": task.description,
               "output": task.result, "status": task.status, "timestamp": now_ts()}
        state.history.append(row)
        if self.enable_prompt_optimization:
            self._optimize_local_profile(state, row)

    def _execute_local_task(self, engine: "BorgEngine", task: PromptTask) -> str:
        kind = task.meta.get("kind")
        metrics = engine.model.metrics()
        with engine.lock:
            domains = [(d, dict(v)) for d, v in engine.domains.items()]
            allowlist = set(engine.allowlist)
            blocklist = set(engine.blocklist)
            rules = set(engine.rule_domains)
        if kind == "model_metrics":
            examples = int(metrics.get("examples", 0) or 0)
            positives = int(metrics.get("positives", 0) or 0)
            negatives = int(metrics.get("negatives", 0) or 0)
            accuracy = metrics.get("accuracy")
            accuracy_text = "not available" if accuracy is None else f"{float(accuracy):.1%} (online estimate, not held-out validation)"
            balance = "balanced enough for an initial model" if min(positives, negatives) > 0 and max(positives, negatives) <= 3 * min(positives, negatives) else "imbalanced or insufficiently labeled; collect verified examples from both classes"
            return f"Training examples: {examples}; positive: {positives}; negative: {negatives}. Online accuracy estimate: {accuracy_text}. Assessment: {balance}."
        if kind == "feedback_conflicts":
            conflicts = []
            for domain, stats in domains:
                label = stats.get("label")
                if label is None:
                    continue
                score = engine.model.probability(domain_features(domain))
                if int(label) == 0 and score >= 0.70:
                    conflicts.append((score, domain, "confirmed legitimate but model score is high"))
                elif int(label) == 1 and score <= 0.30:
                    conflicts.append((1.0-score, domain, "confirmed ad/tracker but model score is low"))
            conflicts.sort(reverse=True)
            if not conflicts:
                return "No strong feedback/model conflicts found at the current 0.70/0.30 review thresholds. This does not establish that the model is accurate."
            return "Potential feedback conflicts (review, do not auto-change labels): " + "; ".join(f"{d} ({reason}; score={engine.model.probability(domain_features(d)):.3f})" for _, d, reason in conflicts[:10])
        if kind == "list_consistency":
            overlap = sorted(allowlist & blocklist)
            rule_allow = sorted(allowlist & rules)
            return f"Allowlist entries: {len(allowlist)}; blocklist entries: {len(blocklist)}; cached rule domains: {len(rules)}. Allow/block overlap: {len(overlap)}. Allowlisted domains also appearing in filter rules: {len(rule_allow)}. BORG normally removes allow/block overlap during load; verify any rule-vs-allow decisions intentionally."
        if kind == "coverage_gaps":
            unlabeled = [(d, int(st.get("observations", 0) or 0), float(st.get("score", engine.model.probability(domain_features(d))) or 0))
                         for d, st in domains if st.get("label") is None]
            unlabeled.sort(key=lambda x: (-x[1], -x[2], x[0]))
            if not unlabeled:
                return "All currently observed domains have explicit labels, or no domains have been observed. Continue checking labels against real browsing outcomes."
            return f"Unlabeled observed domains: {len(unlabeled)}. Highest-observation review candidates: " + "; ".join(f"{d} (observations={n}, score={score:.3f})" for d, n, score in unlabeled[:10]) + ". Confirm from evidence before labeling."
        if kind == "safe_actions":
            suggestions = []
            if int(metrics.get("examples", 0) or 0) < 30:
                suggestions.append("collect more human-confirmed examples from both ad/tracker and legitimate classes")
            if not allowlist:
                suggestions.append("label known legitimate services to reduce false positives")
            if not blocklist:
                suggestions.append("confirm known ad/tracker domains before relying on learned scores")
            if any(st.get("label") is None for _, st in domains):
                suggestions.append("review the highest-observation unlabeled domains in the AI Learning tab")
            if engine.config.get("auto_block_enabled", False):
                suggestions.append("keep automatic blocking conservative and require evidence; predictions alone are not proof")
            if not suggestions:
                suggestions.append("continue reviewing new recommendations and monitor feedback conflicts")
            return "Prioritized next steps: " + "; ".join(suggestions) + ". No settings or lists were changed."
        return "No local evaluator exists for this task type."

    def _optimize_local_profile(self, state: PromptAgentState, row: dict[str, Any]) -> None:
        # Safe deterministic adaptation; never lets model output rewrite system rules.
        output = str(row.get("output") or "")
        state.prompt_profile["style"] = "evidence-first"
        state.prompt_profile["verbosity"] = "detailed" if len(output) > 700 else "concise"
        state.prompt_profile["last_task_status"] = row.get("status", "unknown")



class BorgSignalPhysicsEngine:
    """A lightweight, explainable time-series engine for risk-flow estimates.

    The name describes signal smoothing and inertia, not physical simulation.
    It forecasts aggregate observed risk only; it does not claim certainty.
    """
    def __init__(self):
        self.last_predictions = {"short": 0.0, "medium": 0.0, "long": 0.0,
                                "baseline": 0.0, "best_guess": 0.0, "meta_conf": 0.0}
        self.meta_state = "Warming up"
        self.stance = "Conservative"
        self.model_integrity = 1.0
        self.last_reasoning = ["Waiting for observed-domain history."]
        self.last_heatmap = {}
        self._aggregate_history = deque(maxlen=120)
        self._lock = threading.RLock()

    def update(self, domains: dict[str, dict[str, Any]], model: Any, mesh: Any = None) -> dict[str, Any]:
        scores = []
        labeled = 0
        observations = 0
        for domain, stats in list(domains.items()):
            try:
                score = clamp(float(stats.get("score", model.probability(domain_features(domain)))))
                weight = min(10.0, 1.0 + math.log1p(max(0, int(stats.get("observations", 0)))))
                scores.append((score, weight))
                observations += max(0, int(stats.get("observations", 0)))
                labeled += int(stats.get("label") is not None)
            except Exception:
                continue
        baseline = (sum(v*w for v,w in scores) / sum(w for _,w in scores)) if scores else 0.0
        now = now_ts()
        with self._lock:
            self._aggregate_history.append((now, baseline))
            values = [v for _, v in self._aggregate_history]
            short = sum(values[-3:]) / len(values[-3:]) if values else baseline
            medium_values = values[-10:]
            medium = sum(medium_values) / len(medium_values) if medium_values else baseline
            long_values = values[-30:]
            long = sum(long_values) / len(long_values) if long_values else baseline
            delta = (values[-1] - values[0]) if len(values) > 1 else 0.0
            volatility = (sum(abs(values[i]-values[i-1]) for i in range(1,len(values))) / (len(values)-1)) if len(values)>1 else 0.0
            # Inertia dampens noisy swings while allowing sustained movement through.
            best = clamp(0.45*short + 0.35*medium + 0.20*long + max(-0.08, min(0.08, delta*0.25)))
            coverage = min(1.0, len(scores)/20.0)
            label_coverage = labeled / max(1, len(scores))
            confidence = clamp(0.55*coverage + 0.30*label_coverage + 0.15*(1.0-min(1.0, volatility*3)))
            if not scores:
                state = "Warming up"
            elif volatility >= 0.12:
                state = "Volatile"
            elif delta >= 0.08:
                state = "Risk rising"
            elif delta <= -0.08:
                state = "Risk falling"
            else:
                state = "Stable"
            stance = "Conservative" if confidence < 0.45 or volatility > 0.10 else ("Alert" if best >= 0.65 else "Balanced")
            self.meta_state, self.stance = state, stance
            self.last_predictions = {"short": clamp(short), "medium": clamp(medium), "long": clamp(long),
                                     "baseline": clamp(baseline), "best_guess": best, "meta_conf": confidence,
                                     "trend_delta": delta, "volatility": volatility, "domains": len(scores),
                                     "observations": observations}
            self.model_integrity = clamp(1.0 - min(0.65, volatility*1.8) - (0.15 if len(scores) < 3 else 0.0))
            self.last_reasoning = [
                f"Observed domains contributing to aggregate: {len(scores)}.",
                f"Weighted baseline risk: {baseline:.3f}; smoothed best guess: {best:.3f}.",
                f"Trend delta: {delta:+.3f}; signal volatility: {volatility:.3f}.",
                f"Human-labeled coverage: {label_coverage:.1%}; estimates remain advisory.",
            ]
            self.last_heatmap = {"short": round(short,3), "medium": round(medium,3),
                                 "long": round(long,3), "baseline": round(baseline,3),
                                 "best_guess": round(best,3), "volatility": round(volatility,3),
                                 "confidence": round(confidence,3), "domain_count": len(scores)}
            return dict(self.last_predictions)


class BorgMesh:
    """Local observation graph. It does not crawl sites or enforce/block anything."""
    def __init__(self, max_nodes: int = 2000, max_edges: int = 5000):
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: set[tuple[str, str]] = set()
        self.pid_domains: dict[str, set[str]] = {}
        self.max_nodes = max(100, int(max_nodes))
        self.max_edges = max(100, int(max_edges))
        self._lock = threading.RLock()

    def observe(self, domain: str, score: float, info: dict | None = None, decision: str = "observe / review"):
        info = info or {}
        pid = str(info.get("pid") or "")
        now = now_ts()
        with self._lock:
            node = self.nodes.setdefault(domain, {"state": "observed", "risk": clamp(score), "seen": 0, "last_seen": now, "pid_count": 0})
            node.update({"state": "observed", "risk": clamp(score), "last_seen": now, "decision": str(decision)[:80]})
            node["seen"] = min(1_000_000, int(node.get("seen", 0)) + 1)
            if pid and pid != "None":
                prior = self.pid_domains.setdefault(pid, set())
                for other in prior:
                    if other != domain:
                        self.edges.add(tuple(sorted((domain, other))))
                prior.add(domain)
                node["pid_count"] = len(prior)
            while len(self.nodes) > self.max_nodes:
                oldest = min(self.nodes, key=lambda d: self.nodes[d].get("last_seen", 0))
                self.nodes.pop(oldest, None)
                self.edges = {edge for edge in self.edges if oldest not in edge}
                for known_pid in list(self.pid_domains):
                    self.pid_domains[known_pid].discard(oldest)
                    if not self.pid_domains[known_pid]:
                        self.pid_domains.pop(known_pid, None)
            if len(self.edges) > self.max_edges:
                self.edges = set(list(self.edges)[-self.max_edges:])

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"nodes": len(self.nodes), "edges": len(self.edges),
                    "high_risk": sum(1 for n in self.nodes.values() if n.get("risk",0) >= 0.7),
                    "repeated": sum(1 for n in self.nodes.values() if n.get("seen",0) > 1)}

    def snapshot(self) -> list[tuple[str, dict[str, Any]]]:
        with self._lock:
            return [(d, dict(v)) for d, v in self.nodes.items()]

    def edge_snapshot(self) -> list[tuple[str, str]]:
        with self._lock:
            return sorted(self.edges)


class BorgEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.model = OnlineLogisticModel()
        self.config = DEFAULT_CONFIG.copy()
        loaded_config = read_json(CONFIG_PATH, {})
        if isinstance(loaded_config, dict):
            self.config.update({k: v for k, v in loaded_config.items() if k in DEFAULT_CONFIG})
        self.allowlist = set()
        self.blocklist = set()
        self.reputation = read_json(REPUTATION_PATH, {})
        self.knowledge = read_json(KNOWLEDGE_PATH, {"patterns": [], "last_update": 0})
        self.domains = {}
        self.connections = []
        self.active_title = ""
        self.active_pid = None
        self.active_domain = None
        self.running = True
        self.scan_count = 0
        self.feedback_count = 0
        self.rules = set()
        self.rule_domains = set()
        self.events_seen = Counter()
        self.ad_analyzer = AdAnalyzer()
        self.learning_agent = BorgLearningAgent()
        self.self_prompting_agent = SelfPromptingAgent()
        self.signal_engine = BorgSignalPhysicsEngine()
        self.mesh = BorgMesh(self.config.get("mesh_max_nodes", 2000), self.config.get("mesh_max_edges", 5000))
        self.defender_units: dict[str, DefenderUnit] = {}
        self.devices: dict[str, dict[str, Any]] = {}  # key: ip, value: info
        self._load_custom_lists()
        self._load_cached_rules()

    def _load_custom_lists(self):
        data = read_json(CONFIG_PATH, {})
        self.allowlist = {d for x in data.get("allowlist", []) if (d := normalize_domain(x))}
        self.blocklist = {d for x in data.get("blocklist", []) if (d := normalize_domain(x))}
        self.allowlist -= self.blocklist
        self.save_config()

    def save_config(self):
        try:
            current = read_json(CONFIG_PATH, {})
            current.update(self.config)
            current["allowlist"] = sorted(self.allowlist)
            current["blocklist"] = sorted(self.blocklist)
            atomic_json(CONFIG_PATH, current)
        except Exception as e:
            LOG.log(f"Config save failed: {e}", "ERROR")

    def _load_cached_rules(self):
        for file in RULE_DIR.glob("*.txt") if RULE_DIR.exists() else []:
            try:
                for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    self._parse_rule(line)
            except Exception:
                pass

    def _parse_rule(self, line: str):
        line = line.strip()
        if not line or line.startswith(("!", "#", "[", "@@")):
            return
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            d = normalize_domain(parts[1])
            if d:
                self.rule_domains.add(d)
            return
        if line.startswith("||"):
            candidate = line[2:]
            candidate = re.split(r"[\^/$*|]", candidate, maxsplit=1)[0]
            d = normalize_domain(candidate)
            if d and "." in d:
                self.rule_domains.add(d)
        self.rules.add(line)

    def sync_rules(self):
        RULE_DIR.mkdir(parents=True, exist_ok=True)
        if requests is None:
            LOG.log("Rule sync unavailable: install requests or use cached lists.", "WARN")
            return
        known_before_sync = set(self.rule_domains)
        for i, url in enumerate(RULE_URLS):
            try:
                r = requests.get(url, timeout=(5, 20), headers={"User-Agent": USER_AGENT})
                r.raise_for_status()
                text = r.text[:20_000_000]
                target = RULE_DIR / f"list_{i}.txt"
                temp = target.with_suffix(".tmp")
                temp.write_text(text, encoding="utf-8")
                temp.replace(target)
                with self.lock:
                    for line in text.splitlines():
                        self._parse_rule(line)
                LOG.log(f"Updated filter list {i + 1}; {len(self.rule_domains)} domain hints currently parsed.")
            except Exception as e:
                LOG.log(f"Rule list {i + 1} update failed: {e}", "WARN")
        newly_seen = list(self.rule_domains - known_before_sync)[:10000]
        for d in newly_seen:
            self.model.learn(domain_features(d), 1)
        if newly_seen:
            LOG.log(f"Model learned from {len(newly_seen)} newly discovered rule-domain hints.")
        self.save_reputation()

    def classify(self, domain: str, connection: dict | None = None):
        """Return an explainable risk estimate; prediction is not proof."""
        d = normalize_domain(domain)
        if not d:
            return {"domain": domain, "score": 0.0, "decision": "ignored",
                    "family": "unknown", "evidence": [], "confidence": "none"}
        features = domain_features(d)
        base_score = self.model.probability(features)
        score = base_score
        evidence = [k.replace("_", " ") for k, v in features.items()
                    if v and k not in ("numeric_label", "long_host", "many_labels", "subdomain_depth")]
        # Suffix lookup is proportional to domain depth, not total filter-list size.
        labels = d.split(".")
        rule_hit = any(".".join(labels[i:]) in self.rule_domains for i in range(len(labels) - 1))
        with self.lock:
            stats = dict(self.domains.get(d, {}))
            explicit = stats.get("label")
            observations = int(stats.get("observations", 0))
            history = list(stats.get("history", []))
        if rule_hit:
            score = max(score, 0.99)
            evidence.append("filter-list match")
        if explicit is not None:
            score = 0.99 if explicit == 1 else 0.01
            evidence.append("user-confirmed label")
        window = max(10, int(self.config.get("prediction_window_seconds", 120)))
        cutoff = now_ts() - window
        recent = sum(1 for item in history if isinstance(item, (list, tuple))
                     and len(item) >= 2 and item[0] >= cutoff)
        burst_threshold = max(2, int(self.config.get("burst_observation_threshold", 6)))
        burst = recent >= burst_threshold
        if burst:
            evidence.append(f"recent activity burst ({recent}/{window}s)")
            if explicit is None and not rule_hit:
                score = min(0.90, score + min(0.12, 0.02 * (recent - burst_threshold + 1)))
        # Conservative temporal signal: prioritize review, never treat trend as proof.
        trend_delta = 0.0
        valid_history = []
        for item in history[-max(2, int(self.config.get("trend_history_points", 10))):]:
            try:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    valid_history.append((float(item[0]), clamp(float(item[1]))))
            except (TypeError, ValueError):
                continue
        if len(valid_history) >= 2:
            trend_delta = valid_history[-1][1] - valid_history[0][1]
            if trend_delta > 0.10:
                evidence.append(f"risk score rising (delta {trend_delta:+.2f})")
            elif trend_delta < -0.10:
                evidence.append(f"risk score falling (delta {trend_delta:+.2f})")
        trend_cap = clamp(float(self.config.get("trend_adjustment_cap", 0.08)), 0.0, 0.15)
        trend_adjustment = clamp(trend_delta, -1.0, 1.0) * trend_cap
        if explicit is None and not rule_hit and d not in self.allowlist and d not in self.blocklist:
            score = clamp(score + trend_adjustment)
        priority = clamp(0.70 * score + 0.20 * min(1.0, recent / max(1, burst_threshold)) +
                         0.10 * (1.0 if trend_delta > 0.10 else 0.0))
        if d in self.allowlist:
            decision = "allowlisted"
        elif d in self.blocklist:
            decision = "explicitly blocked (pending hosts apply)"
        elif explicit == 0:
            decision = "allowed (false positive feedback)"
        elif rule_hit:
            decision = "block candidate (filter list)"
        elif (score >= float(self.config.get("auto_block_threshold", 0.94))
              and observations >= int(self.config.get("minimum_evidence", 8))
              and not self.config.get("require_rule_or_feedback", True)):
            decision = "high-confidence candidate"
        else:
            decision = "observe / review"
        confidence = "high" if explicit is not None or rule_hit else (
            "moderate" if observations >= int(self.config.get("minimum_evidence", 8)) else "low"
        )
        return {"domain": d, "score": score, "base_score": base_score,
                "decision": decision, "family": family_for(d), "evidence": evidence,
                "observations": observations, "rule_hit": rule_hit,
                "trusted": bool(rule_hit or explicit == 1), "confidence": confidence,
                "recent_observations": recent, "burst_detected": burst,
                "trend_delta": trend_delta, "trend_adjustment": trend_adjustment,
                "priority": priority, "features": features}

    def observe(self, domain: str, info: dict | None = None):
        d = normalize_domain(domain)
        if not d:
            return
        now = now_ts()
        result = self.classify(d, info)
        with self.lock:
            stats = self.domains.setdefault(d, {
                "first_seen": now, "last_seen": now, "observations": 0,
                "score": result["score"], "family": result["family"],
                "ports": [], "pids": [], "history": [], "label": None,
            })
            stats["observations"] = min(1_000_000, stats["observations"] + 1)
            stats["last_seen"] = now
            stats["score"] = result["score"]
            stats["family"] = result["family"]
            if info:
                port = info.get("port")
                pid = info.get("pid")
                if port and port not in stats["ports"]:
                    stats["ports"] = (stats["ports"] + [port])[-12:]
                if pid and pid not in stats["pids"]:
                    stats["pids"] = (stats["pids"] + [pid])[-12:]
            stats["history"].append([now, result["score"]])
            stats["history"] = stats["history"][-50:]
            self.reputation[d] = {
                "first_seen": stats["first_seen"], "last_seen": now,
                "observations": stats["observations"], "score": result["score"],
                "family": result["family"], "label": stats.get("label"),
            }
            if len(self.domains) > int(self.config.get("max_domains", 3000)):
                oldest = sorted(self.domains.items(), key=lambda kv: kv[1].get("last_seen", 0))[:max(1, len(self.domains)-int(self.config.get("max_domains", 3000)))]
                for old, _ in oldest:
                    self.domains.pop(old, None)
        self.events_seen[result["decision"]] += 1
        try:
            self.mesh.observe(d, result["score"], info, result["decision"])
        except Exception as exc:
            LOG.log(f"Mesh observation skipped: {exc}", "WARN")
        return result

    def label_domain(self, domain: str, label: int):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Please enter a valid public domain name.")
        features = domain_features(d)
        self.model.learn(features, 1 if label else 0)
        with self.lock:
            stats = self.domains.setdefault(d, {"first_seen": now_ts(), "observations": 0, "history": [], "ports": [], "pids": []})
            stats["label"] = 1 if label else 0
            stats["last_seen"] = now_ts()
            stats["score"] = self.model.probability(features)
            stats["family"] = family_for(d)
            self.reputation[d] = {"first_seen": stats.get("first_seen", now_ts()), "last_seen": now_ts(),
                                  "observations": stats.get("observations", 0), "score": stats["score"],
                                  "family": stats["family"], "label": stats["label"]}
            if label:
                self.blocklist.add(d)
                self.allowlist.discard(d)
            else:
                self.allowlist.add(d)
                self.blocklist.discard(d)
            self.feedback_count += 1
        self.save_config()
        self.save_reputation()
        try:
            self.learning_agent._audit({"action": "human_feedback", "domain": d, "label": int(bool(label)), "source": "GUI_or_engine"})
        except Exception:
            pass
        LOG.log(f"Learned explicit {'ad/tracker' if label else 'legitimate/allow'} label for {d}.")
        return self.classify(d)

    def save_reputation(self):
        try:
            atomic_json(REPUTATION_PATH, self.reputation)
            atomic_json(KNOWLEDGE_PATH, {"patterns": [], "last_update": now_ts(),
                                        "note": "Version 10.0 stores explicit labels, model weights, bounded learning-agent review state and audit events, defender units, local network metadata, and conservative temporal review signals; predictions are not proof."})
        except Exception as e:
            LOG.log(f"Could not save reputation/knowledge: {e}", "ERROR")

    def add_block(self, domain: str):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Invalid domain.")
        self.blocklist.add(d)
        self.allowlist.discard(d)
        self.save_config()

    def add_allow(self, domain: str):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Invalid domain.")
        self.allowlist.add(d)
        self.blocklist.discard(d)
        self.save_config()

    def remove_domain(self, domain: str):
        d = normalize_domain(domain)
        if d:
            self.blocklist.discard(d)
            self.allowlist.discard(d)
            self.save_config()

    def scan_connections(self):
        rows = []
        if psutil is None:
            return rows
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as e:
            LOG.log(f"Network scan limited (permissions/platform): {e}", "WARN")
            return rows
        for c in conns:
            try:
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                port = c.raddr.port
                pid = c.pid
                host = None
                if ip and not ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                    host = self.cached_reverse_dns(ip)
                row = {"pid": pid, "ip": ip, "port": port, "host": host, "status": c.status}
                rows.append(row)
                if host:
                    self.observe(host, row)
            except Exception:
                continue
        with self.lock:
            self.connections = rows[-2000:]
            self.scan_count += 1
        return rows

    def cached_reverse_dns(self, ip: str):
        cache = self.reputation.get("_dns_cache", {})
        item = cache.get(ip)
        if item and now_ts() - item.get("ts", 0) < 3600:
            return item.get("host")
        result = [None]
        def lookup():
            try:
                result[0] = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                pass
        t = threading.Thread(target=lookup, daemon=True)
        t.start()
        t.join(0.25)
        if result[0]:
            cache[ip] = {"host": result[0], "ts": now_ts()}
            self.reputation["_dns_cache"] = cache
        return result[0]

    def detect_active_window(self):
        if not IS_WINDOWS:
            return "", None
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return "", None
            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(max(1, length + 1))
            user32.GetWindowTextW(hwnd, buf, len(buf))
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return buf.value.strip(), int(pid.value) or None
        except Exception:
            return "", None

    def self_check(self) -> dict[str, Any]:
        """Read-only integrity checks; logs problems without rewriting application code."""
        checks = {
            "classify_callable": callable(getattr(self, "classify", None)),
            "observe_callable": callable(getattr(self, "observe", None)),
            "model_probability_callable": callable(getattr(self.model, "probability", None)),
            "config_is_dict": isinstance(self.config, dict),
            "signal_engine_ready": isinstance(self.signal_engine, BorgSignalPhysicsEngine),
            "mesh_ready": isinstance(self.mesh, BorgMesh),
        }
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            LOG.log("Integrity check failed: " + ", ".join(failed), "ERROR")
        else:
            LOG.log("Integrity check passed.", "DEBUG")
        return {"ok": not failed, "checks": checks, "failed": failed, "time": iso_time()}

    def monitor_loop(self):
        while self.running:
            try:
                title, pid = self.detect_active_window()
                domain = None
                for token in re.findall(r"(?i)(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}", title or ""):
                    domain = normalize_domain(token)
                    if domain:
                        break
                with self.lock:
                    self.active_title, self.active_pid, self.active_domain = title, pid, domain
                self.scan_connections()
                if domain:
                    self.observe(domain, {"pid": pid, "source": "active-window-title"})
                if self.config.get("auto_block_enabled"):
                    self.auto_block_candidates()
                if self.config.get("agent_enabled", True):
                    self.learning_agent.review(self)
            except Exception as e:
                LOG.log(f"Monitor loop error: {e}", "ERROR")
            time.sleep(max(0.5, float(self.config.get("monitor_interval", 2.0))))

    def auto_block_candidates(self):
        if not self.config.get("auto_block_enabled"):
            return []
        applied = []
        threshold = float(self.config.get("auto_block_threshold", 0.94))
        minimum = int(self.config.get("minimum_evidence", 8))
        with self.lock:
            candidates = list(self.domains.items())
        for d, stats in candidates:
            result = self.classify(d)
            if d in self.allowlist:
                continue
            if result.get("rule_hit") or stats.get("label") == 1:
                self.blocklist.add(d)
                applied.append(d)
            elif (not self.config.get("require_rule_or_feedback", True)
                  and result["score"] >= threshold and stats.get("observations", 0) >= minimum):
                self.blocklist.add(d)
                applied.append(d)
        if applied:
            self.save_config()
            LOG.log(f"Auto-block candidate list updated with {len(applied)} domains.")
        return applied

    def create_defender_for_domain(self, domain: str, sample_url: str | None = None) -> DefenderUnit | None:
        d = normalize_domain(domain)
        if not d:
            return None
        result = self.classify(d)
        family = result["family"]
        score = result["score"]
        payload_path = None
        if sample_url:
            payload_path = self.ad_analyzer.fetch_payload(sample_url, d)
        unit = self.ad_analyzer.analyze_payload(payload_path, d, family, score)
        with self.lock:
            self.defender_units[d] = unit
        LOG.log(f"Created Defender Unit for {d} (family={family}, score={score:.3f})")
        return unit

    def scan_local_network(self):
        """
        Lightweight local network scan:
        - Uses ARP table (arp -a) to discover devices.
        - Optionally uses a CIDR from config for ping sweep (if set).
        - Populates self.devices with IP, MAC, hostname, last_seen.
        """
        devices = {}
        # ARP-based discovery
        try:
            if IS_WINDOWS:
                cmd = ["arp", "-a"]
            else:
                cmd = ["arp", "-a"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
            for line in out.splitlines():
                # Windows: 192.168.1.10          00-11-22-33-44-55     dynamic
                # *nix:   ? (192.168.1.10) at 00:11:22:33:44:55 [ether] on eth0
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                mac = mac_match.group(0) if mac_match else ""
                devices[ip] = {"ip": ip, "mac": mac, "hostname": None, "last_seen": iso_time(), "protected_hint": ""}
        except Exception as e:
            LOG.log(f"Local network ARP scan failed: {e}", "WARN")

        # Resolve hostnames
        for ip, info in devices.items():
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = None
            info["hostname"] = host
            info["protected_hint"] = "Use LAN proxy as HTTP proxy" if self.config.get("lan_proxy_enabled") else "Hosts-based blocking only"

        with self.lock:
            self.devices.update(devices)
        LOG.log(f"Local network scan discovered {len(devices)} devices.")
        return devices

    def shutdown(self):
        self.running = False
        self.model.save()
        self.save_config()
        self.save_reputation()

def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

class HostsApplier:
    MARK_START = "# BEGIN BORG AI ADDEFENDER MANAGED BLOCK"
    MARK_END = "# END BORG AI ADDEFENDER MANAGED BLOCK"

    def __init__(self, engine: BorgEngine):
        self.engine = engine

    def apply(self, domains: list[str] | None = None):
        if not is_admin():
            messagebox.showinfo("Administrator required", "Run as administrator to modify the system hosts file.")
            return False
        selected = set(domains if domains is not None else self.engine.blocklist)
        selected = {d for x in selected if (d := normalize_domain(x))}
        selected -= self.engine.allowlist
        if not selected:
            messagebox.showinfo("Nothing to apply", "There are no valid block entries after allowlist exclusions.")
            return False
        try:
            HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            original = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
            backup = BACKUP_DIR / f"hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup.write_text(original, encoding="utf-8")
            pattern = re.compile(re.escape(self.MARK_START) + r".*?" + re.escape(self.MARK_END), re.S)
            cleaned = pattern.sub("", original).rstrip()
            block = "\n" + self.MARK_START + "\n"
            block += "# Generated by BORG AI AdDefender. Restore from Backups to undo.\n"
            block += "".join(f"0.0.0.0 {d}\n" for d in sorted(selected))
            block += self.MARK_END + "\n"
            temp = HOSTS_PATH.with_suffix(".borg.tmp")
            temp.write_text(cleaned + "\n" + block, encoding="utf-8")
            temp.replace(HOSTS_PATH)
            LOG.log(f"Applied {len(selected)} domains to system hosts file; backup: {backup}")
            messagebox.showinfo("Hosts updated", f"Applied {len(selected)} domains.\nBackup:\n{backup}")
            return True
        except Exception as e:
            LOG.log(f"Hosts update failed: {e}", "ERROR")
            messagebox.showerror("Hosts update failed", f"{e}")
            return False

    def remove_managed_block(self):
        if not is_admin():
            messagebox.showinfo("Administrator required", "Run as administrator to modify the system hosts file.")
            return False
        try:
            original = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
            backup = BACKUP_DIR / f"hosts_before_remove_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup.write_text(original, encoding="utf-8")
            pattern = re.compile(re.escape(self.MARK_START) + r".*?" + re.escape(self.MARK_END), re.S)
            updated = pattern.sub("", original).rstrip() + "\n"
            temp = HOSTS_PATH.with_suffix(".borg.tmp")
            temp.write_text(updated, encoding="utf-8")
            temp.replace(HOSTS_PATH)
            LOG.log("Removed BORG-managed hosts section.")
            messagebox.showinfo("Removed", f"BORG-managed entries removed.\nBackup:\n{backup}")
            return True
        except Exception as e:
            messagebox.showerror("Remove failed", str(e))
            return False

class LANProxyHandler(BaseHTTPRequestHandler):
    engine: BorgEngine = None

    def log_message(self, format, *args):
        LOG.log(f"LANProxy: {self.address_string()} {format % args}", "INFO")

    def do_GET(self):
        try:
            url = self.path
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname or self.headers.get("Host", "")
            domain = normalize_domain(host)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                self.send_error(400, "Use an absolute http:// or https:// URL")
                return
            try:
                import ipaddress
                literal_ip = ipaddress.ip_address(parsed.hostname)
                if not literal_ip.is_global:
                    self.send_error(403, "Private/local destinations are blocked")
                    return
            except ValueError:
                if parsed.hostname.lower() in ("localhost", "localhost.localdomain"):
                    self.send_error(403, "Local destinations are blocked")
                    return
            if not domain:
                self.send_error(502, "Invalid host")
                return
            result = self.engine.classify(domain)
            if result["decision"].startswith("block") or result["family"].endswith("candidate"):
                unit = self.engine.create_defender_for_domain(domain, sample_url=url if parsed.scheme in ("http", "https") else None)
                html_body = unit.render_html()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_body.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(html_body.encode("utf-8"))
                return
            if parsed.scheme not in ("http", "https"):
                url = "http://" + host + self.path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    limit = max(1024, min(20_000_000, int(self.engine.config.get("proxy_max_response_bytes", 5_000_000))))
                    data = resp.read(limit + 1)
                    if len(data) > limit:
                        self.send_error(502, f"Upstream response exceeded {limit}-byte safety limit")
                        return
                    self.send_response(resp.status)
                    for k, v in resp.getheaders():
                        if k.lower() == "transfer-encoding":
                            continue
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(data)
            except Exception as e:
                LOG.log(f"LANProxy forward failed for {url}: {e}", "WARN")
                self.send_error(502, "Upstream error")
        except Exception as e:
            LOG.log(f"LANProxy handler error: {e}", "ERROR")
            self.send_error(500, "Internal proxy error")

class LANProxyServer:
    def __init__(self, engine: BorgEngine):
        self.engine = engine
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self):
        if self.server:
            return
        bind = self.engine.config.get("lan_proxy_bind", "127.0.0.1")
        port = int(self.engine.config.get("lan_proxy_port", 8081))
        try:
            handler_cls = LANProxyHandler
            handler_cls.engine = self.engine
            if bind in ("0.0.0.0", "::"):
                LOG.log("WARNING: LAN proxy is exposed on all interfaces; use only on a trusted network.", "WARN")
            last_error = None
            for candidate_port in [port] + list(range(max(1024, port + 1), min(65536, port + 21))):
                try:
                    self.server = ThreadingHTTPServer((bind, candidate_port), handler_cls)
                    port = candidate_port
                    break
                except OSError as exc:
                    last_error = exc
            if self.server is None:
                raise OSError(f"No available proxy port near {port}: {last_error}")
            self.server.daemon_threads = True
            self.thread = threading.Thread(target=self.server.serve_forever, name="BORG-LANProxy", daemon=True)
            self.thread.start()
            self.engine.config["lan_proxy_port"] = port
            self.engine.save_config()
            LOG.log(f"LAN HTTP proxy started on {bind}:{port}. This basic server does not implement HTTPS CONNECT.")
        except Exception as e:
            LOG.log(f"LAN proxy start failed: {e}", "WARN")
            self.server = None
            self.thread = None

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
            self.thread = None
            LOG.log("LAN HTTP proxy stopped.")

class AdBlockGUI:
    def __init__(self, engine: BorgEngine):
        self.engine = engine
        self.applier = HostsApplier(engine)
        self.lan_proxy = LANProxyServer(engine)
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} — Adaptive Learning {APP_VERSION}")
        self.root.geometry("1020x720")
        self.root.minsize(840, 580)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        self._schedule_refresh()

    def _build(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="BORG AI AdDefender", font=("Segoe UI", 17, "bold")).pack(side="left")
        ttk.Label(header, text="Predictive review • Signal Physics • Observation Mesh • Defender Units").pack(side="left", padx=12)
        self.status = ttk.Label(header, text="Monitoring starting…")
        self.status.pack(side="right")
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        self.monitor_tab = ttk.Frame(self.notebook, padding=8)
        self.learning_tab = ttk.Frame(self.notebook, padding=8)
        self.rules_tab = ttk.Frame(self.notebook, padding=8)
        self.defender_tab = ttk.Frame(self.notebook, padding=8)
        self.settings_tab = ttk.Frame(self.notebook, padding=8)
        self.intelligence_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.monitor_tab, text="Live Monitor")
        self.notebook.add(self.learning_tab, text="AI Learning & Review")
        self.notebook.add(self.rules_tab, text="Block / Allow Lists")
        self.notebook.add(self.defender_tab, text="Defender Units & LAN & Devices")
        self.notebook.add(self.settings_tab, text="Settings & Recovery")
        self.notebook.add(self.intelligence_tab, text="Intelligence & Mesh")
        self._build_monitor()
        self._build_learning()
        self._build_lists()
        self._build_defender()
        self._build_settings()
        self._build_intelligence()

        self.log_box = tk.Text(outer, height=6, wrap="word", state="disabled")
        self.log_box.pack(fill="x", pady=(8, 0))
        ttk.Label(outer, text=f"System hosts file: {HOSTS_PATH}  |  Local state: {BASE_DIR}", foreground="#666").pack(anchor="w", pady=(4, 0))

    def _build_monitor(self):
        top = ttk.Frame(self.monitor_tab)
        top.pack(fill="x")
        self.kpis = {}
        for key, title in (("scan", "Scans"), ("domains", "Observed domains"), ("model", "Training examples"), ("score", "Active-site score")):
            box = ttk.LabelFrame(top, text=title, padding=8)
            box.pack(side="left", fill="x", expand=True, padx=3)
            val = ttk.Label(box, text="—", font=("Segoe UI", 14, "bold"))
            val.pack()
            self.kpis[key] = val
        self.active_label = ttk.Label(self.monitor_tab, text="Active window: —", wraplength=900)
        self.active_label.pack(anchor="w", pady=8)
        cols = ("domain", "score", "family", "observations", "decision")
        self.domain_tree = ttk.Treeview(self.monitor_tab, columns=cols, show="headings", height=15)
        for col, width in zip(cols, (280, 90, 200, 100, 230)):
            self.domain_tree.heading(col, text=col.title())
            self.domain_tree.column(col, width=width, anchor="w")
        self.domain_tree.pack(fill="both", expand=True)
        bar = ttk.Frame(self.monitor_tab)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Scan now", command=self.scan_now).pack(side="left", padx=3)
        ttk.Button(bar, text="Label selected as ad/tracker", command=lambda: self.label_selected(1)).pack(side="left", padx=3)
        ttk.Button(bar, text="Label selected as legitimate", command=lambda: self.label_selected(0)).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh view", command=self.refresh).pack(side="left", padx=3)

    def _build_learning(self):
        self.metrics_text = tk.Text(self.learning_tab, height=9, wrap="word", state="disabled")
        self.metrics_text.pack(fill="x", pady=(0, 8))
        ttk.Label(self.learning_tab, text="Predictive review: burst activity and score trends prioritize investigation; a prediction is not proof. Explicit labels improve the model.").pack(anchor="w")
        agent_bar = ttk.Frame(self.learning_tab)
        agent_bar.pack(fill="x", pady=(6, 3))
        ttk.Button(agent_bar, text="Run learning-agent review", command=self.run_agent_review).pack(side="left", padx=3)
        ttk.Button(agent_bar, text="Export agent report…", command=self.export_agent_report).pack(side="left", padx=3)
        ttk.Button(agent_bar, text="Run self-prompting plan", command=self.run_self_prompting_plan).pack(side="left", padx=3)
        ttk.Button(agent_bar, text="Export plan…", command=self.export_self_prompting_plan).pack(side="left", padx=3)
        self.agent_text = tk.Text(self.learning_tab, height=6, wrap="word", state="disabled")
        self.agent_text.pack(fill="x", pady=(2, 6))
        ttk.Label(self.learning_tab, text="Self-prompting plan: local evidence review by default; optional LLM integration is not configured. No automatic blocking from agent recommendations.").pack(anchor="w", pady=(2, 2))
        self.self_prompt_text = tk.Text(self.learning_tab, height=7, wrap="word", state="disabled")
        self.self_prompt_text.pack(fill="x", pady=(2, 6))
        cols = ("domain", "score", "observations", "label", "family")
        self.review_tree = ttk.Treeview(self.learning_tab, columns=cols, show="headings", height=14)
        for col, width in zip(cols, (300, 100, 120, 100, 240)):
            self.review_tree.heading(col, text=col.title())
            self.review_tree.column(col, width=width, anchor="w")
        self.review_tree.pack(fill="both", expand=True, pady=6)
        row = ttk.Frame(self.learning_tab)
        row.pack(fill="x")
        ttk.Button(row, text="Confirm ad / tracker", command=lambda: self.label_selected(1, review=True)).pack(side="left", padx=3)
        ttk.Button(row, text="Mark legitimate", command=lambda: self.label_selected(0, review=True)).pack(side="left", padx=3)
        ttk.Button(row, text="Export model metrics", command=self.export_metrics).pack(side="left", padx=3)

    def _build_lists(self):
        panes = ttk.Panedwindow(self.rules_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Labelframe(panes, text="Block candidates / explicit blocks", padding=6)
        right = ttk.Labelframe(panes, text="Allowlist (always wins)", padding=6)
        panes.add(left, weight=1); panes.add(right, weight=1)
        self.block_list = tk.Listbox(left, height=18)
        self.block_list.pack(fill="both", expand=True)
        self.allow_list = tk.Listbox(right, height=18)
        self.allow_list.pack(fill="both", expand=True)
        controls = ttk.Frame(self.rules_tab)
        controls.pack(fill="x", pady=8)
        ttk.Button(controls, text="Add block domain…", command=lambda: self.prompt_domain("block")).pack(side="left", padx=3)
        ttk.Button(controls, text="Add allow domain…", command=lambda: self.prompt_domain("allow")).pack(side="left", padx=3)
        ttk.Button(controls, text="Remove selected", command=self.remove_list_selection).pack(side="left", padx=3)
        ttk.Button(controls, text="Import domain list…", command=self.import_list).pack(side="left", padx=3)
        ttk.Button(controls, text="Export lists…", command=self.export_lists).pack(side="left", padx=3)

    def _build_defender(self):
        frame = ttk.Frame(self.defender_tab)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Defender Units: intercepted ads/tracker domains converted into explanatory shields.").pack(anchor="w", pady=(0, 6))
        cols = ("domain", "family", "score", "created_at")
        self.defender_tree = ttk.Treeview(frame, columns=cols, show="headings", height=10)
        for col, width in zip(cols, (260, 220, 80, 180)):
            self.defender_tree.heading(col, text=col.title())
            self.defender_tree.column(col, width=width, anchor="w")
        self.defender_tree.pack(fill="x", expand=False)
        bar = ttk.Frame(frame)
        bar.pack(fill="x", pady=8)
        ttk.Button(bar, text="Generate Defender for selected domain", command=self.generate_defender_for_selected).pack(side="left", padx=3)
        ttk.Button(bar, text="Open Defender folder", command=lambda: self.open_path(DEFENDER_DIR)).pack(side="left", padx=3)

        ttk.Separator(frame).pack(fill="x", pady=8)
        ttk.Label(frame, text="Local Network Devices (ARP-discovered):").pack(anchor="w", pady=(0, 4))
        dev_cols = ("ip", "hostname", "mac", "protected_hint", "last_seen")
        self.device_tree = ttk.Treeview(frame, columns=dev_cols, show="headings", height=10)
        for col, width in zip(dev_cols, (140, 220, 160, 220, 140)):
            self.device_tree.heading(col, text=col.title())
            self.device_tree.column(col, width=width, anchor="w")
        self.device_tree.pack(fill="both", expand=True)
        dev_bar = ttk.Frame(frame)
        dev_bar.pack(fill="x", pady=6)
        ttk.Button(dev_bar, text="Scan local network devices", command=self.scan_devices).pack(side="left", padx=3)
        ttk.Button(dev_bar, text="Open data folder", command=lambda: self.open_path(BASE_DIR)).pack(side="left", padx=3)

    def _build_intelligence(self):
        frame = ttk.Frame(self.intelligence_tab)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="BORG Signal / Data-Flow Engine", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Smoothed aggregate risk signals and local co-observation graph. Estimates are advisory, not physical measurements or proof of malicious activity.", wraplength=900).pack(anchor="w", pady=(2, 8))
        metrics = ttk.Frame(frame)
        metrics.pack(fill="x", pady=(0, 8))
        self.intel_labels = {}
        for key, title in (("state", "Meta-State"), ("stance", "Review Stance"), ("confidence", "Meta-Confidence"), ("integrity", "Signal Integrity"), ("risk", "Best Guess Risk"), ("mesh", "Mesh Nodes / Edges")):
            box = ttk.LabelFrame(metrics, text=title, padding=6)
            box.pack(side="left", fill="x", expand=True, padx=2)
            label = ttk.Label(box, text="—", font=("Segoe UI", 10, "bold"))
            label.pack()
            self.intel_labels[key] = label
        self.signal_canvas = tk.Canvas(frame, height=190, background="#111111", highlightthickness=0)
        self.signal_canvas.pack(fill="x", expand=False, pady=4)
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Run integrity check", command=self.run_integrity_check).pack(side="left", padx=3)
        ttk.Button(row, text="Refresh signal engine", command=self.update_intelligence_view).pack(side="left", padx=3)
        ttk.Button(row, text="Export mesh snapshot…", command=self.export_mesh_snapshot).pack(side="left", padx=3)
        self.intel_reasoning = tk.Text(frame, height=12, wrap="word")
        self.intel_reasoning.pack(fill="both", expand=True, pady=(4, 0))
        self.update_intelligence_view()
        self.root.after(15000, self._schedule_integrity_check)

    def _schedule_integrity_check(self):
        if not self.root.winfo_exists():
            return
        self.run_integrity_check(show_popup=False)
        self.root.after(15000, self._schedule_integrity_check)

    def run_integrity_check(self, show_popup=True):
        result = self.engine.self_check()
        if show_popup:
            messagebox.showinfo("BORG integrity check", "Integrity check passed." if result["ok"] else "Issues found: " + ", ".join(result["failed"]))
        self.update_intelligence_view()
        return result

    def update_intelligence_view(self):
        try:
            with self.engine.lock:
                domain_snapshot = {d: dict(v) for d, v in self.engine.domains.items()}
            pred = self.engine.signal_engine.update(domain_snapshot, self.engine.model, self.engine.mesh)
            mesh_stats = self.engine.mesh.stats()
            self.intel_labels["state"].config(text=self.engine.signal_engine.meta_state)
            self.intel_labels["stance"].config(text=self.engine.signal_engine.stance)
            self.intel_labels["confidence"].config(text=f'{pred["meta_conf"]:.2f}')
            self.intel_labels["integrity"].config(text=f'{self.engine.signal_engine.model_integrity:.2f}')
            self.intel_labels["risk"].config(text=f'{pred["best_guess"]:.3f}')
            self.intel_labels["mesh"].config(text=f'{mesh_stats["nodes"]} / {mesh_stats["edges"]}')
            c = self.signal_canvas
            c.delete("all")
            w = max(200, int(c.winfo_width()))
            h = max(100, int(c.winfo_height()))
            c.create_rectangle(0, 0, w, h, fill="#111111", outline="")
            vals = [("Short", pred["short"], "#00ccff"), ("Medium", pred["medium"], "#66ff66"), ("Long", pred["long"], "#ffaa33"), ("Baseline", pred["baseline"], "#888888"), ("Best guess", pred["best_guess"], "#ff66dd")]
            c.create_line(8, h-18, w-8, h-18, fill="#555555")
            for i, (name, val, color) in enumerate(vals):
                x = int((i+0.5) * w / len(vals))
                y = h - 24 - int(clamp(val) * (h-45))
                c.create_line(x, h-18, x, y, fill=color, width=3)
                c.create_oval(x-4, y-4, x+4, y+4, fill=color, outline=color)
                c.create_text(x, h-10, text=f"{name} {val:.2f}", fill="#dddddd", anchor="s")
            lines = ["Signal reasoning:"] + [" • " + x for x in self.engine.signal_engine.last_reasoning]
            lines += ["", "Signal summary:"] + [f" • {k}: {v}" for k,v in self.engine.signal_engine.last_heatmap.items()]
            lines += ["", f"Mesh nodes: {mesh_stats['nodes']} | edges: {mesh_stats['edges']} | high-risk hints: {mesh_stats['high_risk']} | repeated observations: {mesh_stats['repeated']}"]
            lines += ["", "Mesh edges mean two domains were observed under the same process ID; this is correlation, not proof that one domain caused or controls the other."]
            self.intel_reasoning.delete("1.0", tk.END)
            self.intel_reasoning.insert("1.0", "\n".join(lines))
        except Exception as exc:
            LOG.log(f"Intelligence view update failed: {exc}", "WARN")

    def export_mesh_snapshot(self):
        path = filedialog.asksaveasfilename(title="Export BORG mesh snapshot", defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            payload = {"created_at": iso_time(), "stats": self.engine.mesh.stats(),
                       "nodes": [{"domain": d, **meta} for d, meta in self.engine.mesh.snapshot()],
                       "edges": [list(e) for e in self.engine.mesh.edge_snapshot()]}
            Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved mesh snapshot to {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _build_settings(self):
        frame = ttk.Frame(self.settings_tab)
        frame.pack(fill="both", expand=True, anchor="nw")
        self.auto_var = tk.BooleanVar(value=bool(self.engine.config.get("auto_block_enabled", False)))
        self.strict_var = tk.BooleanVar(value=bool(self.engine.config.get("require_rule_or_feedback", True)))
        self.lan_proxy_var = tk.BooleanVar(value=bool(self.engine.config.get("lan_proxy_enabled", False)))
        ttk.Checkbutton(frame, text="Enable automatic candidate additions", variable=self.auto_var).pack(anchor="w", pady=5)
        ttk.Checkbutton(frame, text="Strict mode: only rule evidence or explicit user confirmation", variable=self.strict_var).pack(anchor="w", pady=5)
        ttk.Checkbutton(frame, text="Enable LAN HTTP proxy (protect devices via proxy)", variable=self.lan_proxy_var).pack(anchor="w", pady=5)
        ttk.Label(frame, text="Auto-block threshold (0.50–0.999)").pack(anchor="w", pady=(14, 2))
        self.threshold_var = tk.DoubleVar(value=float(self.engine.config.get("auto_block_threshold", 0.94)))
        ttk.Scale(frame, from_=0.5, to=0.999, variable=self.threshold_var, orient="horizontal").pack(fill="x", padx=3)
        ttk.Label(frame, text="Minimum observations before heuristic-only candidates are considered").pack(anchor="w", pady=(14, 2))
        self.minimum_var = tk.IntVar(value=int(self.engine.config.get("minimum_evidence", 8)))
        ttk.Spinbox(frame, from_=1, to=10000, textvariable=self.minimum_var, width=10).pack(anchor="w")
        ttk.Button(frame, text="Save settings", command=self.save_settings).pack(anchor="w", pady=10)
        ttk.Separator(frame).pack(fill="x", pady=10)
        ttk.Button(frame, text="Sync filter lists now", command=self.sync_rules).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Apply selected block list to system hosts…", command=self.apply_hosts).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Remove BORG-managed hosts section…", command=self.remove_hosts).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Open backup folder", command=lambda: self.open_path(BACKUP_DIR)).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Open data folder", command=lambda: self.open_path(BASE_DIR)).pack(anchor="w", pady=3)

    def run_agent_review(self):
        try:
            report = self.engine.learning_agent.review(self.engine, force=True)
            self._render_agent_report(report)
            messagebox.showinfo("Learning-agent review", f"Reviewed {report.get('domains_reviewed', 0)} domains.\nRecommendations: {len(report.get('recommendations', []))}\n\nNo domains were automatically blocked by this review.")
        except Exception as e:
            LOG.log(f"Learning-agent review failed: {e}", "ERROR")
            messagebox.showerror("Agent review failed", str(e))

    def run_self_prompting_plan(self):
        try:
            report = self.engine.self_prompting_agent.run(self.engine)
            self._render_self_prompting_report(report)
            completed = sum(1 for task in report.get("tasks", []) if task.get("status") == "done")
            messagebox.showinfo("Self-prompting plan", f"Completed {completed}/{len(report.get('tasks', []))} analysis tasks.\nMode: {report.get('mode', 'local-evidence')}\n\nNo blocklists, allowlists, or hosts-file entries were changed.")
        except Exception as exc:
            LOG.log(f"Self-prompting plan failed: {exc}", "ERROR")
            messagebox.showerror("Self-prompting plan failed", str(exc))

    def _render_self_prompting_report(self, report: dict[str, Any]):
        if not hasattr(self, "self_prompt_text"):
            return
        lines = [f"Generated: {report.get('generated_at', 'not run')} | Mode: {report.get('mode', 'local-evidence')} | Steps: {report.get('steps', 0)}",
                 f"Goal: {report.get('goal', '')}",
                 f"Adaptive profile: {json.dumps(report.get('prompt_profile', {}), ensure_ascii=False)}", ""]
        for task in report.get("tasks", []):
            lines.append(f"[{task.get('status', 'unknown').upper()}] {task.get('description', '')}")
            if task.get("result"):
                lines.append(f"  {task['result']}")
        lines.extend(["", report.get("safety_note", "")])
        self.self_prompt_text.config(state="normal")
        self.self_prompt_text.delete("1.0", tk.END)
        self.self_prompt_text.insert("1.0", "\n".join(lines))
        self.self_prompt_text.config(state="disabled")

    def export_self_prompting_plan(self):
        report = self.engine.self_prompting_agent.last_report
        if not report:
            messagebox.showinfo("No plan yet", "Run the self-prompting plan first.")
            return
        path = filedialog.asksaveasfilename(title="Export self-prompting plan", defaultextension=".json",
                                            filetypes=[("JSON report", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved plan to {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _render_agent_report(self, report: dict[str, Any]):
        if not hasattr(self, "agent_text"):
            return
        lines = [f"Last review: {report.get('generated_at', 'not run')} | Cycles: {report.get('cycles', 0)}",
                 f"Domains reviewed: {report.get('domains_reviewed', 0)} | Confirmed labels: {report.get('labeled_domains', 0)}",
                 f"Potential false positives: {report.get('false_positive_candidates', 0)} | Potential false negatives: {report.get('false_negative_candidates', 0)}",
                 "Recommendations (ranked; verify before acting):"]
        for item in report.get("recommendations", [])[:10]:
            lines.append(f"• [{item.get('kind')}] {item.get('domain')} — score {item.get('score', 0):.3f}: {item.get('reason')}")
        if not report.get("recommendations"):
            lines.append("No review recommendations at this time.")
        lines.append(report.get("safety_note", ""))
        self.agent_text.config(state="normal")
        self.agent_text.delete("1.0", tk.END)
        self.agent_text.insert("1.0", "\n".join(lines))
        self.agent_text.config(state="disabled")

    def export_agent_report(self):
        report = self.engine.learning_agent.review(self.engine, force=False)
        path = filedialog.asksaveasfilename(title="Export learning-agent report", defaultextension=".json",
                                            filetypes=[("JSON report", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved report to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def selected_domain(self, review=False):
        tree = self.review_tree if review else self.domain_tree
        sel = tree.selection()
        if not sel:
            return None
        return tree.item(sel[0], "values")[0]

    def label_selected(self, label: int, review=False):
        d = self.selected_domain(review=review)
        if not d:
            messagebox.showinfo("Select a domain", "Select a domain row first.")
            return
        prompt = "Confirm this is an ad/tracker?" if label else "Confirm this is legitimate and should be allowed?"
        if not messagebox.askyesno("Confirm learning label", f"{prompt}\n\n{d}\n\nThis updates the local model and allow/block lists."):
            return
        try:
            self.engine.label_domain(d, label)
            self.refresh()
        except Exception as e:
            messagebox.showerror("Learning failed", str(e))

    def scan_now(self):
        threading.Thread(target=self.engine.scan_connections, daemon=True).start()
        self.status.config(text="Scanning…")
        self.root.after(800, self.refresh)

    def scan_devices(self):
        threading.Thread(target=self.engine.scan_local_network, daemon=True).start()
        self.status.config(text="Scanning local network…")
        self.root.after(1200, self.refresh)

    def refresh(self):
        try:
            domain_sel = self._get_selected_value(self.domain_tree, 0)
            review_sel = self._get_selected_value(self.review_tree, 0)
            defender_sel = self._get_selected_value(self.defender_tree, 0)
            device_sel = self._get_selected_value(self.device_tree, 0)

            with self.engine.lock:
                domains = list(self.engine.domains.items())
                title = self.engine.active_title
                active = self.engine.active_domain
                scan_count = self.engine.scan_count
                defenders = dict(self.engine.defender_units)
                devices = dict(self.engine.devices)

            self.kpis["scan"].config(text=str(scan_count))
            self.kpis["domains"].config(text=str(len(domains)))
            self.kpis["model"].config(text=str(self.engine.model.metrics()["examples"]))
            active_score = self.engine.classify(active)["score"] if active else 0.0
            self.kpis["score"].config(text=f"{active_score:.3f}")
            self.active_label.config(text=f"Active window: {title or '—'}  |  inferred domain: {active or 'not detected'}")

            for tree in (self.domain_tree, self.review_tree, self.defender_tree, self.device_tree):
                for item in tree.get_children():
                    tree.delete(item)

            rows = []
            for d, stats in domains:
                result = self.engine.classify(d)
                rows.append((d, result, stats))
            rows.sort(key=lambda x: (x[1]["score"], x[2].get("observations", 0)), reverse=True)
            for d, result, stats in rows[:500]:
                self.domain_tree.insert("", "end", values=(d, f'{result["score"]:.3f}', result["family"], stats.get("observations", 0), result["decision"]))
                label = stats.get("label")
                label_text = "Ad/tracker" if label == 1 else "Legitimate" if label == 0 else "Unlabeled"
                self.review_tree.insert("", "end", values=(d, f'{result["score"]:.3f}', stats.get("observations", 0), label_text, result["family"]))

            self.block_list.delete(0, tk.END)
            self.allow_list.delete(0, tk.END)
            for d in sorted(self.engine.blocklist):
                self.block_list.insert(tk.END, d)
            for d in sorted(self.engine.allowlist):
                self.allow_list.insert(tk.END, d)

            for d, unit in sorted(defenders.items(), key=lambda kv: kv[1].score, reverse=True):
                self.defender_tree.insert("", "end", values=(d, unit.family, f"{unit.score:.3f}", unit.created_at))

            for ip, info in sorted(devices.items(), key=lambda kv: kv[0]):
                self.device_tree.insert("", "end", values=(
                    ip,
                    info.get("hostname") or "",
                    info.get("mac") or "",
                    info.get("protected_hint") or "",
                    info.get("last_seen") or "",
                ))

            self._restore_selection(self.domain_tree, domain_sel, 0)
            self._restore_selection(self.review_tree, review_sel, 0)
            self._restore_selection(self.defender_tree, defender_sel, 0)
            self._restore_selection(self.device_tree, device_sel, 0)

            metrics = self.engine.model.metrics()
            acc = "not enough evaluation data" if metrics["accuracy"] is None else f'{metrics["accuracy"]:.1%}'
            text = (
                f"Model: online logistic regression\n"
                f"Training examples: {metrics['examples']}  |  positive: {metrics['positives']}  |  negative: {metrics['negatives']}\n"
                f"Running online accuracy estimate (not held-out validation): {acc}\n"
                f"Explicit feedback this session: {self.engine.feedback_count}\n"
                f"Weights: {json.dumps(metrics['weights'], sort_keys=True)}\n"
            )
            self.metrics_text.config(state="normal")
            self.metrics_text.delete("1.0", tk.END)
            self.metrics_text.insert("1.0", text)
            self.metrics_text.config(state="disabled")
            try:
                self._render_agent_report(self.engine.learning_agent.last_report)
                if self.engine.self_prompting_agent.last_report:
                    self._render_self_prompting_report(self.engine.self_prompting_agent.last_report)
            except Exception:
                pass
            self.update_intelligence_view()
            self.status.config(text=f"Updated {datetime.now().strftime('%H:%M:%S')}")

            if not hasattr(self, "_last_log_ts"):
                self._last_log_ts = 0
            new = [x for x in LOG.snapshot() if x["ts"] > self._last_log_ts]
            if new:
                self.log_box.config(state="normal")
                for row in reversed(new[-12:]):
                    self.log_box.insert(tk.END, f'[{row["time"]}] {row["level"]}: {row["message"]}\n')
                self.log_box.see(tk.END)
                self.log_box.config(state="disabled")
                self._last_log_ts = max(x["ts"] for x in new)
        except Exception as e:
            LOG.log(f"GUI refresh error: {e}", "ERROR")

    def _get_selected_value(self, tree: ttk.Treeview, col_index: int):
        sel = tree.selection()
        if not sel:
            return None
        vals = tree.item(sel[0], "values")
        if not vals:
            return None
        return vals[col_index]

    def _restore_selection(self, tree: ttk.Treeview, value: str | None, col_index: int):
        if not value:
            return
        for item in tree.get_children():
            vals = tree.item(item, "values")
            if vals and vals[col_index] == value:
                tree.selection_set(item)
                tree.focus(item)
                break

    def _schedule_refresh(self):
        self.refresh()
        self.root.after(1500, self._schedule_refresh)

    def prompt_domain(self, mode):
        win = tk.Toplevel(self.root)
        win.title("Add domain")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Domain name (for example, ads.example.com):").pack(padx=12, pady=(12, 4))
        entry = ttk.Entry(win, width=42)
        entry.pack(padx=12, pady=4)
        entry.focus_set()
        def submit():
            try:
                if mode == "block":
                    self.engine.add_block(entry.get())
                else:
                    self.engine.add_allow(entry.get())
                win.destroy()
                self.refresh()
            except Exception as e:
                messagebox.showerror("Invalid domain", str(e), parent=win)
        ttk.Button(win, text="Save", command=submit).pack(pady=10)
        entry.bind("<Return>", lambda _e: submit())

    def remove_list_selection(self):
        box = self.block_list
        sel = box.curselection()
        if not sel:
            messagebox.showinfo("Select a domain", "Select a list entry to remove.")
            return
        domain = box.get(sel[0])
        self.engine.remove_domain(domain)
        self.refresh()

    def import_list(self):
        path = filedialog.askopenfilename(title="Import domain list", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        mode = messagebox.askyesnocancel("Import destination", "Yes = add to block list\nNo = add to allowlist\nCancel = abort")
        if mode is None:
            return
        added = 0
        try:
            for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                parts = line.split()
                d = normalize_domain(parts[-1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else line)
                if d:
                    (self.engine.add_block if mode else self.engine.add_allow)(d)
                    added += 1
            messagebox.showinfo("Import complete", f"Imported {added} valid domain entries.")
            self.refresh()
        except Exception as e:
            messagebox.showerror("Import failed", str(e))

    def export_lists(self):
        path = filedialog.asksaveasfilename(title="Export domain lists", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            lines = ["# BORG AI AdDefender domain export", "[BLOCKLIST]"]
            lines += sorted(self.engine.blocklist)
            lines += ["", "[ALLOWLIST]"] + sorted(self.engine.allowlist)
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved {len(self.engine.blocklist)} block entries and {len(self.engine.allowlist)} allow entries.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def save_settings(self):
        self.engine.config["auto_block_enabled"] = bool(self.auto_var.get())
        self.engine.config["require_rule_or_feedback"] = bool(self.strict_var.get())
        self.engine.config["auto_block_threshold"] = clamp(float(self.threshold_var.get()), 0.5, 0.999)
        self.engine.config["minimum_evidence"] = max(1, int(self.minimum_var.get()))
        self.engine.config["lan_proxy_enabled"] = bool(self.lan_proxy_var.get())
        self.engine.save_config()
        LOG.log("Settings saved.")
        messagebox.showinfo("Settings saved", "Settings saved.")
        if self.engine.config["lan_proxy_enabled"]:
            self.lan_proxy.start()
        else:
            self.lan_proxy.stop()

    def sync_rules(self):
        self.status.config(text="Updating rules…")
        threading.Thread(target=self._sync_rules_worker, daemon=True).start()

    def _sync_rules_worker(self):
        self.engine.sync_rules()
        self.root.after(0, self.refresh)

    def apply_hosts(self):
        if not messagebox.askyesno("Apply to system hosts", "This will write block entries into the system hosts file.\n\nProceed?"):
            return
        domains = list(self.engine.blocklist)
        self.applier.apply(domains)

    def remove_hosts(self):
        if not messagebox.askyesno("Remove BORG-managed hosts section", "This will remove the BORG-managed block section from hosts.\n\nProceed?"):
            return
        self.applier.remove_managed_block()

    def generate_defender_for_selected(self):
        sel = self.domain_tree.selection()
        if not sel:
            messagebox.showinfo("Select a domain", "Select a domain row first.")
            return
        d = self.domain_tree.item(sel[0], "values")[0]
        try:
            unit = self.engine.create_defender_for_domain(d)
            if unit:
                messagebox.showinfo("Defender created", f"Defender Unit created for {d}.\nStored in: {DEFENDER_DIR}")
                self.refresh()
        except Exception as e:
            messagebox.showerror("Defender creation failed", str(e))

    def open_path(self, path: Path):
        try:
            path.mkdir(parents=True, exist_ok=True)
            if IS_WINDOWS:
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def export_metrics(self):
        path = filedialog.asksaveasfilename(title="Export model metrics", defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            metrics = self.engine.model.metrics()
            Path(path).write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved metrics to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def close(self):
        try:
            self.engine.running = False
        except Exception:
            pass
        try:
            self.lan_proxy.stop()
        except Exception:
            pass
        try:
            self.engine.shutdown()
        except Exception:
            pass
        self.root.destroy()

def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    engine = BorgEngine()
    gui = AdBlockGUI(engine)
    t = threading.Thread(target=engine.monitor_loop, name="BORG-Monitor", daemon=True)
    t.start()
    gui.root.mainloop()

if __name__ == "__main__":
    try:
        # Perform elevation before creating the GUI, starting monitoring, or
        # accessing the protected Windows hosts file.
        ensure_admin()
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        LOG.log("Fatal error in main loop.", "ERROR")
