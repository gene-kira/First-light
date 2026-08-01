#!/usr/bin/env python3
# ai_price_system_v4_ai_interpret.py
# Headless autonomous AI shopping + hardware recommendation daemon (with AI result interpretation)
# - Creates project + extension folders
# - Writes browser extension (Manifest v3)
# - Runs local HTTP bridge (/bridge)
# - Watches URLs + queries + AI result text
# - Parses AI hardware intent (AI system vs GPU vs RAM vs SSD vs cloud GPU)
# - Interprets AI result text (prices, products, stores) in a lightweight way
# - Scores hardware vs use-case (Stable Diffusion, Llama 3 70B, generic AI)
# - Picks best candidate (local hardware or cloud GPU)
# - Auto-opens best match
# - Sends Windows toast notifications
# - Logs decisions to console + SQLite
# - No GUI, no traditional scraping

import sys
import subprocess
import importlib
import threading
import time
import re
import os
import sqlite3
import webbrowser
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from datetime import datetime

# ============================================================
# PATHS / BOOTSTRAP
# ============================================================

BASE_DIR = os.path.join(os.path.expanduser("~"), "AIPriceSystem")
EXT_DIR = os.path.join(BASE_DIR, "browser_extension")
CURRENT_URL_FILE = os.path.join(BASE_DIR, "current_url.txt")
CURRENT_QUERY_FILE = os.path.join(BASE_DIR, "current_query.txt")
CURRENT_AI_TEXT_FILE = os.path.join(BASE_DIR, "current_ai_text.txt")
DB_PATH = os.path.join(BASE_DIR, "price_history.db")

def write_file(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[BOOTSTRAP] Wrote {path}")

def bootstrap_extension():
    os.makedirs(EXT_DIR, exist_ok=True)

    manifest = r"""
{
  "manifest_version": 3,
  "name": "AI Price Bridge",
  "version": "1.3",
  "description": "Send current URL, search query, and AI result text to local AI price daemon.",
  "permissions": [
    "tabs",
    "activeTab",
    "scripting"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle"
    }
  ]
}
"""
    write_file(os.path.join(EXT_DIR, "manifest.json"), manifest.strip() + "\n")

    background_js = r"""
const LOCAL_SERVER_URL = "http://127.0.0.1:5000/bridge";

async function sendToDaemon(payload) {
  try {
    const res = await fetch(LOCAL_SERVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    console.log("[AI Price Bridge] Sent payload:", payload, "Status:", res.status);
  } catch (e) {
    console.warn("[AI Price Bridge] Failed to send payload:", e);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") return;

  if (message.type === "URL_UPDATE") {
    const url = message.url;
    if (typeof url === "string" && url.startsWith("http")) {
      sendToDaemon({ kind: "url", value: url });
    }
  }

  if (message.type === "QUERY_UPDATE") {
    const query = message.query;
    if (typeof query === "string" && query.trim().length > 1) {
      sendToDaemon({ kind: "query", value: query.trim() });
    }
  }

  if (message.type === "AI_TEXT_UPDATE") {
    const aiText = message.aiText;
    if (typeof aiText === "string" && aiText.trim().length > 10) {
      sendToDaemon({ kind: "ai_text", value: aiText.trim() });
    }
  }

  sendResponse({ ok: true });
});
"""
    write_file(os.path.join(EXT_DIR, "background.js"), background_js.strip() + "\n")

    content_js = r"""
(function() {
  "use strict";

  function sendCurrentURL() {
    const url = window.location.href;
    if (typeof url === "string" && url.startsWith("http")) {
      chrome.runtime.sendMessage({ type: "URL_UPDATE", url });
    }
  }

  function detectSearchQuery() {
    let query = null;

    const googleBox = document.querySelector("input[name='q']");
    if (googleBox && googleBox.value && googleBox.value.trim().length > 0) {
      query = googleBox.value.trim();
    }

    if (!query) {
      const inputs = Array.from(document.querySelectorAll("input[type='search'], input[name='search'], input[placeholder*='search']"));
      for (const inp of inputs) {
        if (inp.value && inp.value.trim().length > 0) {
          query = inp.value.trim();
          break;
        }
      }
    }

    if (query && query.length > 1) {
      chrome.runtime.sendMessage({ type: "QUERY_UPDATE", query });
    }
  }

  function detectAIResultText() {
    let text = "";

    // Generic heuristic: collect visible text from elements that look like AI answer panels.
    const candidates = [];
    candidates.push(...document.querySelectorAll("[data-content-feature*='ai'], [data-ai-answer], [data-ai-summary]"));
    candidates.push(...document.querySelectorAll("div[role='dialog'], div[role='region']"));

    const seen = new Set();
    for (const el of candidates) {
      if (!el || !el.innerText) continue;
      const t = el.innerText.trim();
      if (t.length < 50) continue;
      if (seen.has(t)) continue;
      seen.add(t);
      text += " " + t;
    }

    if (!text) {
      const bodyText = document.body && document.body.innerText ? document.body.innerText.trim() : "";
      if (bodyText.length > 2000) {
        text = bodyText.slice(0, 2000);
      } else {
        text = bodyText;
      }
    }

    if (text && text.trim().length > 50) {
      chrome.runtime.sendMessage({ type: "AI_TEXT_UPDATE", aiText: text.trim() });
    }
  }

  function init() {
    sendCurrentURL();
    detectSearchQuery();
    detectAIResultText();
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    init();
  } else {
    window.addEventListener("DOMContentLoaded", init);
  }
})();
"""
    write_file(os.path.join(EXT_DIR, "content.js"), content_js.strip() + "\n")

# ============================================================
# AUTLOADER
# ============================================================

class Autoloader:
    def __init__(self):
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "network": {"modules": ["requests"], "install": True},
            "notify": {"modules": ["win10toast"], "install": True},
        }
        self.loaded_modules: Dict[str, Any] = {}
        self.missing_modules: Dict[str, List[str]] = {}
        self.lock = threading.Lock()
        self.predictive_thread: Optional[threading.Thread] = None
        self.predictive_running = False

    def _soft_import(self, module_name: str) -> Optional[Any]:
        try:
            return importlib.import_module(module_name)
        except ImportError:
            return None

    def _hard_install(self, module_name: str) -> bool:
        try:
            print(f"[Autoloader] Installing {module_name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
            return True
        except Exception as e:
            print(f"[Autoloader] Failed to install {module_name}: {e}")
            return False

    def ensure_group(self, group_name: str):
        group = self.dependency_map.get(group_name, {})
        modules = group.get("modules", [])
        allow_install = group.get("install", False)
        missing = []
        for m in modules:
            mod = self._soft_import(m)
            if mod is None:
                missing.append(m)
                if allow_install and self._hard_install(m):
                    mod = self._soft_import(m)
            if mod is not None:
                with self.lock:
                    self.loaded_modules[m] = mod
        if missing:
            with self.lock:
                self.missing_modules[group_name] = missing

    def start_predictive_daemon(self):
        if self.predictive_running:
            return

        def _daemon():
            self.predictive_running = True
            for g in list(self.dependency_map.keys()):
                self.ensure_group(g)
                time.sleep(0.5)
            self.predictive_running = False

        self.predictive_thread = threading.Thread(target=_daemon, daemon=True)
        self.predictive_thread.start()

    def get_module(self, name: str) -> Optional[Any]:
        return self.loaded_modules.get(name)

AUTOLOADER = Autoloader()
AUTOLOADER.start_predictive_daemon()

# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class QueryIntent:
    raw_query: str
    category: Optional[str] = None
    keywords: List[str] = field(default_factory=list)
    max_price: Optional[float] = None
    budget_level: Optional[str] = None
    use_case: Optional[str] = None
    gpu_vram_min: Optional[int] = None
    ram_min: Optional[int] = None
    storage_min: Optional[int] = None
    cpu_cores_min: Optional[int] = None

@dataclass
class HardwareCandidate:
    name: str
    kind: str  # "ai_system", "gpu", "ram", "ssd", "cloud_gpu"
    vram_gb: Optional[int] = None
    ram_gb: Optional[int] = None
    storage_gb: Optional[int] = None
    cpu_cores: Optional[int] = None
    price: float = 0.0
    store: str = ""
    url: Optional[str] = None
    score: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

# ============================================================
# PRICE NORMALIZATION
# ============================================================

class PriceNormalizer:
    @staticmethod
    def normalize_price(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            if isinstance(value, (int, float)):
                return float(value)
            s = re.sub(r"[^\d\.]", "", str(value))
            if not s:
                return None
            return float(s)
        except Exception:
            return None

# ============================================================
# AI HARDWARE KNOWLEDGE BASE + SCORING
# ============================================================

class AIHardwareKB:
    USE_CASE_REQUIREMENTS = {
        "stable_diffusion": {
            "gpu_vram_min": 12,
            "ram_min": 32,
            "storage_min": 1000,
            "cpu_cores_min": 8,
        },
        "llama_3_70b": {
            "gpu_vram_min": 48,
            "ram_min": 64,
            "storage_min": 2000,
            "cpu_cores_min": 16,
        },
        "generic_ai": {
            "gpu_vram_min": 12,
            "ram_min": 32,
            "storage_min": 1000,
            "cpu_cores_min": 8,
        },
    }

    @staticmethod
    def apply_use_case(intent: QueryIntent):
        if not intent.use_case:
            return
        req = AIHardwareKB.USE_CASE_REQUIREMENTS.get(intent.use_case)
        if not req:
            return
        intent.gpu_vram_min = req["gpu_vram_min"]
        intent.ram_min = req["ram_min"]
        intent.storage_min = req["storage_min"]
        intent.cpu_cores_min = req["cpu_cores_min"]

    @staticmethod
    def score_candidate(intent: QueryIntent, cand: HardwareCandidate) -> float:
        score = 0.0

        def contrib(actual: Optional[int], required: Optional[int], weight: float) -> float:
            if required is None or actual is None:
                return 0.0
            if actual < required:
                return -weight
            return weight * (1.0 + (actual - required) / max(required, 1))

        score += contrib(cand.vram_gb, intent.gpu_vram_min, 3.0)
        score += contrib(cand.ram_gb, intent.ram_min, 2.0)
        score += contrib(cand.storage_gb, intent.storage_min, 1.5)
        score += contrib(cand.cpu_cores, intent.cpu_cores_min, 1.5)

        if intent.max_price is not None and cand.kind != "cloud_gpu" and cand.price > intent.max_price:
            score -= 5.0

        if intent.budget_level == "cheap":
            if cand.kind != "cloud_gpu":
                score -= cand.price / 1000.0
        elif intent.budget_level == "high":
            if cand.kind != "cloud_gpu":
                score += cand.price / 1000.0

        return score

# ============================================================
# QUERY PARSER
# ============================================================

class QueryParser:
    @staticmethod
    def _detect_budget_level(q: str) -> Optional[str]:
        if any(w in q for w in ["cheap", "budget", "low cost", "inexpensive"]):
            return "cheap"
        if any(w in q for w in ["midrange", "mid-range", "mid tier"]):
            return "mid"
        if any(w in q for w in ["high-end", "high end", "premium", "expensive"]):
            return "high"
        return None

    @staticmethod
    def _detect_use_case(q: str) -> Optional[str]:
        if "stable diffusion" in q:
            return "stable_diffusion"
        if "llama 3 70b" in q or "llama3 70b" in q or "70b" in q:
            return "llama_3_70b"
        if "ai system" in q or "ai workstation" in q or "ai rig" in q:
            return "generic_ai"
        return None

    @staticmethod
    def _extract_numeric_caps(q: str) -> Dict[str, Optional[int]]:
        caps = {
            "max_price": None,
            "gpu_vram_min": None,
            "ram_min": None,
            "storage_min": None,
            "cpu_cores_min": None,
        }

        m_price = re.search(r"under\s*\$?\s*(\d+)", q)
        if m_price:
            caps["max_price"] = int(m_price.group(1))

        m_vram = re.search(r"(\d+)\s*gb\s*(vram|gpu)", q)
        if m_vram:
            caps["gpu_vram_min"] = int(m_vram.group(1))

        m_ram = re.search(r"(\d+)\s*gb\s*(ram|memory)", q)
        if m_ram:
            caps["ram_min"] = int(m_ram.group(1))

        m_storage = re.search(r"(\d+)\s*(tb|terabyte)", q)
        if m_storage:
            caps["storage_min"] = int(m_storage.group(1)) * 1000

        m_cpu = re.search(r"(\d+)\s*(core|cores)", q)
        if m_cpu:
            caps["cpu_cores_min"] = int(m_cpu.group(1))

        return caps

    @staticmethod
    def parse(raw_query: str) -> QueryIntent:
        q = raw_query.lower()
        keywords = re.findall(r"[a-z0-9]+", q)

        if "ai" in keywords and "system" in keywords:
            category = "ai_system"
        elif "workstation" in keywords or "rig" in keywords:
            category = "ai_system"
        elif "gpu" in keywords or "graphics" in keywords:
            category = "gpu"
        elif "memory" in keywords or "ram" in keywords:
            category = "memory"
        elif "ssd" in keywords or "nvme" in keywords or "storage" in keywords:
            category = "ssd"
        else:
            category = "generic"

        budget_level = QueryParser._detect_budget_level(q)
        use_case = QueryParser._detect_use_case(q)
        caps = QueryParser._extract_numeric_caps(q)

        intent = QueryIntent(
            raw_query=raw_query,
            category=category,
            keywords=keywords,
            max_price=float(caps["max_price"]) if caps["max_price"] is not None else None,
            budget_level=budget_level,
            use_case=use_case,
            gpu_vram_min=caps["gpu_vram_min"],
            ram_min=caps["ram_min"],
            storage_min=caps["storage_min"],
            cpu_cores_min=caps["cpu_cores_min"],
        )

        if intent.use_case:
            AIHardwareKB.apply_use_case(intent)

        return intent

# ============================================================
# AI RESULT INTERPRETER
# ============================================================

class AIResultInterpreter:
    @staticmethod
    def extract_prices(ai_text: str) -> List[float]:
        prices = []
        for match in re.findall(r"\$\s*\d{1,5}(?:\.\d{1,2})?", ai_text):
            val = PriceNormalizer.normalize_price(match)
            if val is not None:
                prices.append(val)
        for match in re.findall(r"\d{1,5}(?:\.\d{1,2})?\s*USD", ai_text, flags=re.IGNORECASE):
            val = PriceNormalizer.normalize_price(match)
            if val is not None:
                prices.append(val)
        return prices

    @staticmethod
    def extract_stores(ai_text: str) -> List[str]:
        stores = []
        known = ["amazon", "newegg", "microcenter", "best buy", "bestbuy", "walmart", "dell", "hp", "lenovo",
                 "lambda", "runpod", "vast.ai", "vast", "paperspace"]
        lower = ai_text.lower()
        for s in known:
            if s in lower:
                stores.append(s)
        return list(dict.fromkeys(stores))

    @staticmethod
    def extract_products(ai_text: str) -> List[str]:
        products = []
        for m in re.findall(r"(rtx\s*\d{3,4}\s*(?:super)?)", ai_text, flags=re.IGNORECASE):
            products.append(m.strip())
        for m in re.findall(r"(\d+\s*gb\s*(?:ddr4|ddr5|ram|memory))", ai_text, flags=re.IGNORECASE):
            products.append(m.strip())
        for m in re.findall(r"(\d+\s*tb\s*(?:ssd|nvme|storage))", ai_text, flags=re.IGNORECASE):
            products.append(m.strip())
        return list(dict.fromkeys(products))

    @staticmethod
    def summarize(ai_text: str) -> Dict[str, Any]:
        prices = AIResultInterpreter.extract_prices(ai_text)
        stores = AIResultInterpreter.extract_stores(ai_text)
        products = AIResultInterpreter.extract_products(ai_text)
        return {
            "prices": prices,
            "stores": stores,
            "products": products,
        }

# ============================================================
# PRICE HISTORY
# ============================================================

class PriceHistory:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS prices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                context TEXT,
                store TEXT,
                price REAL,
                currency TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()

    def record_price(self, context: str, store: str, price: float, currency: str = "USD"):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO prices (context, store, price, currency, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (context, store, price, currency, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    def get_average_price(self, context: str) -> Optional[float]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT AVG(price) FROM prices WHERE context = ?", (context,))
        row = cur.fetchone()
        conn.close()
        if row and row[0] is not None:
            return float(row[0])
        return None

# ============================================================
# MULTI-STORE ENGINE + CLOUD GPU STUBS
# ============================================================

class MultiStoreAPIEngine:
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys or {}

    def candidates_for_intent(self, intent: QueryIntent, ai_summary: Optional[Dict[str, Any]] = None) -> List[HardwareCandidate]:
        cands: List[HardwareCandidate] = []

        # Base candidates (same as v3)
        if intent.category == "ai_system":
            cands.extend([
                HardwareCandidate(
                    name="Lambda AI Workstation",
                    kind="ai_system",
                    vram_gb=48,
                    ram_gb=128,
                    storage_gb=2000,
                    cpu_cores=24,
                    price=4500.0,
                    store="Lambda Labs",
                    url="https://example.com/lambda-ai-system",
                ),
                HardwareCandidate(
                    name="Dell Precision AI",
                    kind="ai_system",
                    vram_gb=24,
                    ram_gb=64,
                    storage_gb=2000,
                    cpu_cores=16,
                    price=3200.0,
                    store="Dell",
                    url="https://example.com/dell-ai-system",
                ),
                HardwareCandidate(
                    name="Budget AI Tower",
                    kind="ai_system",
                    vram_gb=12,
                    ram_gb=32,
                    storage_gb=1000,
                    cpu_cores=8,
                    price=1500.0,
                    store="Generic",
                    url="https://example.com/budget-ai-system",
                ),
            ])
        elif intent.category == "gpu":
            cands.extend([
                HardwareCandidate(
                    name="RTX 4090",
                    kind="gpu",
                    vram_gb=24,
                    price=1800.0,
                    store="Amazon",
                    url="https://example.com/rtx4090",
                ),
                HardwareCandidate(
                    name="RTX 4080 Super",
                    kind="gpu",
                    vram_gb=16,
                    price=1200.0,
                    store="Newegg",
                    url="https://example.com/rtx4080s",
                ),
                HardwareCandidate(
                    name="RTX 4070",
                    kind="gpu",
                    vram_gb=12,
                    price=800.0,
                    store="MicroCenter",
                    url="https://example.com/rtx4070",
                ),
            ])
        elif intent.category == "memory":
            cands.extend([
                HardwareCandidate(
                    name="64GB DDR5 Kit",
                    kind="ram",
                    ram_gb=64,
                    price=250.0,
                    store="Amazon",
                    url="https://example.com/64gb-ddr5",
                ),
                HardwareCandidate(
                    name="32GB DDR5 Kit",
                    kind="ram",
                    ram_gb=32,
                    price=130.0,
                    store="Newegg",
                    url="https://example.com/32gb-ddr5",
                ),
            ])
        elif intent.category == "ssd":
            cands.extend([
                HardwareCandidate(
                    name="2TB NVMe Gen4",
                    kind="ssd",
                    storage_gb=2000,
                    price=180.0,
                    store="Amazon",
                    url="https://example.com/2tb-nvme",
                ),
                HardwareCandidate(
                    name="1TB NVMe Gen4",
                    kind="ssd",
                    storage_gb=1000,
                    price=100.0,
                    store="BestBuy",
                    url="https://example.com/1tb-nvme",
                ),
            ])
        else:
            cands.extend([
                HardwareCandidate(
                    name="Generic GPU",
                    kind="gpu",
                    vram_gb=12,
                    price=600.0,
                    store="Amazon",
                    url="https://example.com/generic-gpu",
                ),
                HardwareCandidate(
                    name="Generic AI Tower",
                    kind="ai_system",
                    vram_gb=12,
                    ram_gb=32,
                    storage_gb=1000,
                    cpu_cores=8,
                    price=1600.0,
                    store="Generic",
                    url="https://example.com/generic-ai",
                ),
            ])

        # Cloud GPU candidates
        cands.extend([
            HardwareCandidate(
                name="RunPod A100 80GB",
                kind="cloud_gpu",
                vram_gb=80,
                ram_gb=256,
                storage_gb=2000,
                cpu_cores=32,
                price=2.5,
                store="RunPod",
                url="https://example.com/runpod-a100",
                meta={"pricing_model": "hourly"},
            ),
            HardwareCandidate(
                name="Vast.ai 4090",
                kind="cloud_gpu",
                vram_gb=24,
                ram_gb=128,
                storage_gb=1000,
                cpu_cores=16,
                price=1.2,
                store="Vast.ai",
                url="https://example.com/vast-4090",
                meta={"pricing_model": "hourly"},
            ),
        ])

        # Adjust candidates based on AI summary (if present)
        if ai_summary:
            prices = ai_summary.get("prices", [])
            stores = ai_summary.get("stores", [])
            products = ai_summary.get("products", [])

            if prices:
                avg_ai_price = sum(prices) / len(prices)
                for c in cands:
                    if c.kind != "cloud_gpu":
                        c.price = max(c.price * 0.9, avg_ai_price * 0.8)

            for c in cands:
                for s in stores:
                    if s.lower() in c.store.lower():
                        c.price *= 0.95

            for c in cands:
                for p in products:
                    if p.lower() in c.name.lower():
                        c.price *= 0.9

        return cands

    def pick_best_candidate(self, intent: QueryIntent, ai_summary: Optional[Dict[str, Any]] = None) -> Optional[HardwareCandidate]:
        cands = self.candidates_for_intent(intent, ai_summary)
        if not cands:
            return None

        best: Optional[HardwareCandidate] = None
        for c in cands:
            c.score = AIHardwareKB.score_candidate(intent, c)
            print(f"[Engine] Candidate: {c.name} ({c.kind}) @ {c.store} price={c.price} score={c.score:.2f}")
            if best is None or c.score > best.score:
                best = c

        return best

# ============================================================
# NOTIFICATIONS
# ============================================================

class NotificationEngine:
    def __init__(self):
        win10toast = AUTOLOADER.get_module("win10toast")
        if win10toast is None:
            self.toaster = None
            print("[Notify] 'win10toast' missing")
        else:
            self.toaster = win10toast.ToastNotifier()

    def notify_best_candidate(self, intent: QueryIntent, cand: HardwareCandidate, avg_price: Optional[float]):
        if self.toaster is None:
            return
        title = f"Best match for: {intent.raw_query}"
        if cand.kind == "cloud_gpu":
            msg = f"{cand.store} {cand.name}: ${cand.price:.2f}/hr (score {cand.score:.2f})"
        else:
            msg = f"{cand.store} {cand.name}: ${cand.price:.2f} (score {cand.score:.2f})"
        if avg_price is not None and cand.kind != "cloud_gpu":
            msg += f" | Avg: ${avg_price:.2f}"
        self.toaster.show_toast(title, msg, duration=10, threaded=True)
        print(f"[Notify] {title} -> {msg}")

# ============================================================
# BROWSER WATCHER
# ============================================================

class BrowserWatcher:
    def __init__(self):
        self.last_url: Optional[str] = None
        self.last_query: Optional[str] = None
        self.last_ai_text: Optional[str] = None

    def _read_file(self, path: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                s = f.read().strip()
            return s or None
        except Exception:
            return None

    def get_current_url(self) -> Optional[str]:
        return self._read_file(CURRENT_URL_FILE)

    def get_current_query(self) -> Optional[str]:
        return self._read_file(CURRENT_QUERY_FILE)

    def get_current_ai_text(self) -> Optional[str]:
        return self._read_file(CURRENT_AI_TEXT_FILE)

    def has_new_query(self) -> Optional[str]:
        q = self.get_current_query()
        if not q:
            return None
        if q == self.last_query:
            return None
        self.last_query = q
        return q

    def has_new_ai_text(self) -> Optional[str]:
        t = self.get_current_ai_text()
        if not t:
            return None
        if t == self.last_ai_text:
            return None
        self.last_ai_text = t
        return t

# ============================================================
# DAEMON
# ============================================================

class PriceDaemon:
    def __init__(self, interval_seconds: int = 30):
        self.interval = interval_seconds
        self.browser = BrowserWatcher()
        self.history = PriceHistory()
        self.api_engine = MultiStoreAPIEngine(api_keys={})
        self.notifier = NotificationEngine()
        self.running = False
        self.latest_ai_summary: Optional[Dict[str, Any]] = None

    def auto_open_candidate(self, cand: HardwareCandidate):
        if cand.url:
            try:
                webbrowser.open(cand.url)
                print(f"[Daemon] Auto-opened {cand.store}: {cand.url}")
            except Exception as e:
                print(f"[Daemon] Failed to open browser: {e}")
        else:
            print("[Daemon] No URL for candidate")

    def process_ai_text(self, ai_text: str):
        print("[Daemon] New AI result text received (truncated):")
        print(ai_text[:300] + ("..." if len(ai_text) > 300 else ""))
        summary = AIResultInterpreter.summarize(ai_text)
        self.latest_ai_summary = summary
        print(f"[Daemon] AI summary: prices={summary['prices']}, stores={summary['stores']}, products={summary['products']}")

    def process_query(self, raw_query: str):
        print(f"[Daemon] Query: {raw_query}")
        intent = QueryParser.parse(raw_query)
        print(f"[Daemon] Parsed intent: category={intent.category}, budget={intent.budget_level}, use_case={intent.use_case}, "
              f"max_price={intent.max_price}, gpu_vram_min={intent.gpu_vram_min}, ram_min={intent.ram_min}, "
              f"storage_min={intent.storage_min}, cpu_cores_min={intent.cpu_cores_min}")

        best = self.api_engine.pick_best_candidate(intent, self.latest_ai_summary)
        if not best:
            print("[Daemon] No candidate found")
            return

        if best.kind != "cloud_gpu":
            self.history.record_price(intent.raw_query, best.store, best.price, "USD")
            avg_price = self.history.get_average_price(intent.raw_query)
        else:
            avg_price = None

        print(f"[Daemon] Best candidate: {best.name} ({best.kind}) from {best.store} price={best.price} score={best.score:.2f}")
        self.notifier.notify_best_candidate(intent, best, avg_price)
        self.auto_open_candidate(best)

    def run_loop(self):
        self.running = True
        print("AI Price System v4 (AI result interpretation, headless) running.")
        print(f"- Extension folder: {EXT_DIR}")
        print("- In Chrome/Edge: Extensions → Developer mode → Load unpacked → select browser_extension")
        print("- Then use AI search (Google/Bing/store AI) with queries like 'cheap ai system for llama 3 70b under 1500'.\n")

        while self.running:
            ai_text = self.browser.has_new_ai_text()
            if ai_text:
                self.process_ai_text(ai_text)

            q = self.browser.has_new_query()
            if q:
                self.process_query(q)

            time.sleep(self.interval)

# ============================================================
# HTTP BRIDGE
# ============================================================

class BridgeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/bridge":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            data = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        kind = data.get("kind")
        value = data.get("value")
        if not isinstance(value, str) or len(value.strip()) < 1:
            self.send_response(400)
            self.end_headers()
            return

        if kind == "url":
            write_file(CURRENT_URL_FILE, value.strip())
        elif kind == "query":
            write_file(CURRENT_QUERY_FILE, value.strip())
        elif kind == "ai_text":
            write_file(CURRENT_AI_TEXT_FILE, value.strip())
        else:
            self.send_response(400)
            self.end_headers()
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def start_bridge_server():
    server = HTTPServer(("127.0.0.1", 5000), BridgeHandler)
    print("[Bridge] HTTP bridge on http://127.0.0.1:5000/bridge")
    server.serve_forever()

# ============================================================
# MAIN
# ============================================================

def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    bootstrap_extension()

    daemon = PriceDaemon(interval_seconds=30)

    bridge_thread = threading.Thread(target=start_bridge_server, daemon=True)
    bridge_thread.start()

    daemon_thread = threading.Thread(target=daemon.run_loop, daemon=True)
    daemon_thread.start()

    print("[Main] Headless v4 system started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] Stopping daemon...")

if __name__ == "__main__":
    main()
