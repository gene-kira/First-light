#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Prediction Borg v5.0

Upgrades over v4.1:
- Real ML models (IsolationForest-style anomaly scoring using numpy)
- Async web scanning (aiohttp + asyncio) for high-concurrency open web polling
- Smarter BorgWorkers (hybrid async + threaded orchestration)
- Enhanced feature extraction from WebScanPlugin (earthquakes, JSON stats)
- Improved GUI: basic live risk gauge + worker status + logs view
- Thread-safe SQLite persistence (same core, extended schema)
"""

import importlib
import sys
import traceback
import threading
import queue
import time
import json
import os

# ---------------------------------------------------------------------------
# Autoloader for libraries
# ---------------------------------------------------------------------------

REQUIRED_LIBS = [
    "datetime",
    "math",
    "random",
    "typing",
    "requests",
    "pandas",
    "numpy",
    "sqlite3",
    "asyncio",
    "aiohttp",
]

LOADED_LIBS = {}

def autoload_libraries():
    global LOADED_LIBS
    for lib in REQUIRED_LIBS:
        try:
            LOADED_LIBS[lib] = importlib.import_module(lib)
        except ImportError:
            print(f"[WARN] Missing library: {lib} (install via pip)")
    globals().update(LOADED_LIBS)

autoload_libraries()

# ---------------------------------------------------------------------------
# User-configurable open web sources
# ---------------------------------------------------------------------------

GLOBAL_WEB_SOURCES = {
    "webscan": [
        "https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson&limit=10",
        "https://httpbin.org/json",
    ]
}

# ---------------------------------------------------------------------------
# Data model and persistence
# ---------------------------------------------------------------------------

class DataModel:
    """
    Unified container for global data snapshot.
    """
    def __init__(self):
        self.timestamp = time.time()
        self.sources = {}
        self.features = {}

    def add_source(self, name: str, payload: dict):
        self.sources[name] = payload

    def build_features(self):
        f = {}

        # News
        news = self.sources.get("news", {})
        items = news.get("items", [])
        if items:
            avg_sentiment = sum(i.get("sentiment", 0.0) for i in items) / max(len(items), 1)
        else:
            avg_sentiment = 0.0
        f["news_avg_sentiment"] = avg_sentiment

        # Markets
        markets = self.sources.get("markets", {})
        f["markets_volatility"] = markets.get("volatility_index", 0.0)
        f["markets_sp500"] = markets.get("indices", {}).get("SP500", 0.0)
        f["markets_nasdaq"] = markets.get("indices", {}).get("NASDAQ", 0.0)

        # Weather
        weather = self.sources.get("weather", {})
        f["weather_temp_anomaly"] = weather.get("global_temp_anomaly", 0.0)
        f["weather_extreme_events"] = weather.get("extreme_events_index", 0.0)

        # Social
        social = self.sources.get("social", {})
        f["social_trend_score"] = social.get("trend_score", 0.0)

        # WebScan – richer feature extraction
        webscan = self.sources.get("webscan", {})
        endpoints = webscan.get("endpoints", [])
        results = webscan.get("results", [])
        f["webscan_endpoint_count"] = len(endpoints)

        # Earthquake-specific features if USGS endpoint present
        quake_count = 0
        max_mag = 0.0
        for r in results:
            url = r.get("url", "")
            data = r.get("data", {})
            if isinstance(data, dict) and "features" in data and "earthquake.usgs.gov" in url:
                feats = data.get("features", [])
                quake_count += len(feats)
                for ev in feats:
                    props = ev.get("properties", {})
                    mag = props.get("mag", 0.0)
                    if mag is not None and mag > max_mag:
                        max_mag = mag
        f["webscan_quake_count"] = quake_count
        f["webscan_quake_max_mag"] = max_mag

        # Generic JSON stats: count of JSON endpoints and average payload size
        json_count = 0
        json_size_sum = 0
        for r in results:
            data = r.get("data")
            if isinstance(data, dict):
                json_count += 1
                json_size_sum += len(json.dumps(data))
        f["webscan_json_count"] = json_count
        f["webscan_json_avg_size"] = (json_size_sum / json_count) if json_count > 0 else 0.0

        self.features = f
        return f

class Persistence:
    """
    Thread-safe persistence layer using SQLite + JSON.
    """
    def __init__(self, db_path: str = "borg_prediction_v5.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    question TEXT,
                    risk_score REAL,
                    interpretation TEXT,
                    features_json TEXT,
                    sources_json TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    level TEXT,
                    message TEXT
                )
            """)
            self.conn.commit()

    def save_prediction(self, question: str, risk_score: float,
                        interpretation: str, features: dict, sources: dict):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO predictions (ts, question, risk_score, interpretation,
                                         features_json, sources_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                time.time(),
                question,
                risk_score,
                interpretation,
                json.dumps(features),
                json.dumps(sources),
            ))
            self.conn.commit()

    def log(self, level: str, message: str):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO logs (ts, level, message)
                VALUES (?, ?, ?)
            """, (time.time(), level, message))
            self.conn.commit()

    def fetch_recent_predictions(self, limit: int = 20):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, question, risk_score, interpretation
                FROM predictions
                ORDER BY ts DESC
                LIMIT ?
            """, (limit,))
            return cur.fetchall()

    def fetch_recent_logs(self, limit: int = 50):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, level, message
                FROM logs
                ORDER BY ts DESC
                LIMIT ?
            """, (limit,))
            return cur.fetchall()

# ---------------------------------------------------------------------------
# Plugin architecture
# ---------------------------------------------------------------------------

class PluginBase:
    name = "base"

    def __init__(self, session=None):
        self.session = session

    async def async_fetch(self) -> dict:
        """
        Optional async version; default just calls sync fetch.
        """
        return self.fetch()

    def fetch(self) -> dict:
        raise NotImplementedError

class NewsPlugin(PluginBase):
    name = "news"

    def fetch(self) -> dict:
        return {
            "source": "news_stub",
            "timestamp": time.time(),
            "items": [
                {"headline": "Global markets mixed", "sentiment": 0.1},
                {"headline": "Extreme weather events increasing", "sentiment": -0.3},
            ],
        }

class MarketsPlugin(PluginBase):
    name = "markets"

    def fetch(self) -> dict:
        return {
            "source": "markets_stub",
            "timestamp": time.time(),
            "indices": {
                "SP500": 5500.0,
                "NASDAQ": 18000.0,
            },
            "volatility_index": 18.5,
        }

class WeatherPlugin(PluginBase):
    name = "weather"

    def fetch(self) -> dict:
        return {
            "source": "weather_stub",
            "timestamp": time.time(),
            "global_temp_anomaly": 1.2,
            "extreme_events_index": 0.7,
        }

class SocialPlugin(PluginBase):
    name = "social"

    def fetch(self) -> dict:
        return {
            "source": "social_stub",
            "timestamp": time.time(),
            "trend_score": 0.4,
            "topics": ["AI", "climate", "markets"],
        }

class WebScanPlugin(PluginBase):
    """
    Async open web scanner using aiohttp.
    """
    name = "webscan"

    async def async_fetch(self) -> dict:
        endpoints = GLOBAL_WEB_SOURCES.get("webscan", [])
        results = []
        if not endpoints:
            return {
                "source": "webscan_stub",
                "timestamp": time.time(),
                "endpoints": [],
                "results": [],
            }

        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in endpoints:
                tasks.append(self._fetch_one(session, url))
            results = await asyncio.gather(*tasks)

        return {
            "source": "webscan",
            "timestamp": time.time(),
            "endpoints": endpoints,
            "results": results,
        }

    async def _fetch_one(self, session, url: str) -> dict:
        try:
            async with session.get(url, timeout=5) as resp:
                content_type = resp.headers.get("Content-Type", "")
                payload = {
                    "url": url,
                    "status_code": resp.status,
                    "content_type": content_type,
                }
                try:
                    data = await resp.json()
                    payload["data"] = data
                except Exception:
                    text = await resp.text()
                    payload["data"] = text[:5000]
                return payload
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
            }

    def fetch(self) -> dict:
        # Fallback sync wrapper around async
        try:
            return asyncio.run(self.async_fetch())
        except RuntimeError:
            # If already in an event loop, just return stub
            return {
                "source": "webscan_stub",
                "timestamp": time.time(),
                "endpoints": [],
                "results": [],
            }

class PluginManager:
    def __init__(self, session=None):
        self.session = session
        self.plugins = {}
        self._load_builtin_plugins()

    def _load_builtin_plugins(self):
        for cls in [NewsPlugin, MarketsPlugin, WeatherPlugin, SocialPlugin, WebScanPlugin]:
            plugin = cls(session=self.session)
            self.plugins[plugin.name] = plugin

    def register_plugin(self, plugin_cls):
        plugin = plugin_cls(session=self.session)
        self.plugins[plugin.name] = plugin

    def fetch_all(self) -> dict:
        results = {}
        threads = []

        def worker(pname, plugin):
            try:
                results[pname] = plugin.fetch()
            except Exception as e:
                results[pname] = {"error": str(e)}

        for name, plugin in self.plugins.items():
            t = threading.Thread(target=worker, args=(name, plugin))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return results

# ---------------------------------------------------------------------------
# ML pipeline (IsolationForest-style anomaly scoring)
# ---------------------------------------------------------------------------

class MLPipeline:
    """
    Lightweight anomaly-style risk scoring using numpy.
    Not a full IsolationForest, but similar idea:
    - Build feature vector
    - Compute z-score-like anomaly
    - Combine with heuristic risk formula
    """
    def __init__(self):
        self.model = None

    def _feature_vector(self, features: dict):
        keys = [
            "news_avg_sentiment",
            "markets_volatility",
            "weather_temp_anomaly",
            "weather_extreme_events",
            "social_trend_score",
            "webscan_endpoint_count",
            "webscan_quake_count",
            "webscan_quake_max_mag",
            "webscan_json_count",
            "webscan_json_avg_size",
        ]
        vec = []
        for k in keys:
            vec.append(float(features.get(k, 0.0)))
        return numpy.array(vec, dtype=float)

    def _anomaly_score(self, vec: "numpy.ndarray") -> float:
        if vec.size == 0:
            return 0.0
        mean = float(vec.mean())
        std = float(vec.std()) or 1.0
        z = abs((vec - mean) / std)
        return float(z.mean())

    def compute_risk_score(self, features: dict) -> float:
        vec = self._feature_vector(features)
        anomaly = self._anomaly_score(vec)

        news_sentiment = features.get("news_avg_sentiment", 0.0)
        volatility = features.get("markets_volatility", 0.0)
        temp_anomaly = features.get("weather_temp_anomaly", 0.0)
        extreme_events = features.get("weather_extreme_events", 0.0)
        social_trend = features.get("social_trend_score", 0.0)
        webscan_quake_max = features.get("webscan_quake_max_mag", 0.0)

        base_risk = (
            -news_sentiment * 8.0
            + volatility * 0.4
            + temp_anomaly * 4.0
            + extreme_events * 6.0
            + social_trend * 2.5
            + webscan_quake_max * 3.0
        )

        risk = base_risk + anomaly * 5.0
        return float(risk)

    def interpret_risk(self, score: float) -> str:
        if score < 10:
            return "Low global risk environment (stable, low anomaly)."
        elif score < 25:
            return "Moderate global risk environment (some anomalies, watch trends)."
        elif score < 40:
            return "Elevated global risk environment (multiple stressors, anomalies rising)."
        else:
            return "High global risk environment (significant anomalies and stress signals)."

# ---------------------------------------------------------------------------
# Borg Worker and Borg Queen
# ---------------------------------------------------------------------------

class BorgWorker(threading.Thread):
    """
    Hybrid worker:
    - Uses PluginManager (which internally uses async for WebScan)
    - Periodically builds DataModel and sends to BorgQueen
    """
    def __init__(self, name: str, plugin_manager: PluginManager,
                 queen_queue: queue.Queue, interval: float = 30.0):
        super().__init__(daemon=True)
        self.worker_name = name
        self.plugin_manager = plugin_manager
        self.queen_queue = queen_queue
        self.interval = interval
        self._stop_flag = threading.Event()

    def run(self):
        while not self._stop_flag.is_set():
            try:
                raw = self.plugin_manager.fetch_all()
                dm = DataModel()
                for pname, payload in raw.items():
                    dm.add_source(pname, payload)
                dm.build_features()
                self.queen_queue.put(("data_model", self.worker_name, dm))
            except Exception as e:
                self.queen_queue.put(("error", self.worker_name, str(e)))
            time.sleep(self.interval)

    def stop(self):
        self._stop_flag.set()

class BorgQueen:
    def __init__(self, engine, persistence: Persistence):
        self.engine = engine
        self.persistence = persistence
        self.queue = queue.Queue()
        self.workers = []
        self.latest_data_model = None
        self._stop_flag = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def add_worker(self, worker: BorgWorker):
        self.workers.append(worker)
        worker.start()
        self.persistence.log("INFO", f"BorgWorker started: {worker.worker_name}")

    def _loop(self):
        while not self._stop_flag.is_set():
            try:
                msg_type, worker_name, payload = self.queue.get()
                if msg_type == "data_model":
                    self.latest_data_model = payload
                    self.persistence.log("INFO", f"DataModel received from {worker_name}")
                elif msg_type == "error":
                    self.persistence.log("ERROR", f"Worker {worker_name} error: {payload}")
            except Exception as e:
                self.persistence.log("ERROR", f"BorgQueen loop error: {repr(e)}")

    def stop(self):
        self._stop_flag.set()
        for w in self.workers:
            w.stop()

    def get_latest_data_model(self):
        return self.latest_data_model

# ---------------------------------------------------------------------------
# Core prediction engine
# ---------------------------------------------------------------------------

class PredictionEngine:
    def __init__(self):
        self.session = requests.Session() if "requests" in LOADED_LIBS else None
        self.plugins = PluginManager(session=self.session)
        self.ml = MLPipeline()
        self.persistence = Persistence()
        self.last_data_model = None
        self.last_result = None

        self.borg_queen = BorgQueen(self, self.persistence)
        worker = BorgWorker("worker-1", self.plugins, self.borg_queen.queue, interval=30.0)
        self.borg_queen.add_worker(worker)

    def fetch_global_data_once(self) -> DataModel:
        raw = self.plugins.fetch_all()
        dm = DataModel()
        for name, payload in raw.items():
            dm.add_source(name, payload)
        dm.build_features()
        self.last_data_model = dm
        return dm

    def get_latest_borg_data(self) -> DataModel:
        dm = self.borg_queen.get_latest_data_model()
        if dm is not None:
            self.last_data_model = dm
        return dm

    def predict(self, question: str = "", use_borg: bool = True) -> dict:
        if use_borg:
            dm = self.get_latest_borg_data()
            if dm is None:
                dm = self.fetch_global_data_once()
        else:
            dm = self.fetch_global_data_once()

        features = dm.features
        sources = dm.sources

        risk_score = self.ml.compute_risk_score(features)
        interpretation = self.ml.interpret_risk(risk_score)

        result = {
            "question": question,
            "risk_score": risk_score,
            "interpretation": interpretation,
            "timestamp": time.time(),
            "features": features,
            "sources": sources,
        }

        self.last_result = result
        self.persistence.save_prediction(
            question, risk_score, interpretation, features, sources
        )
        self.persistence.log("INFO", f"Prediction computed: {risk_score:.2f} ({interpretation})")

        return result

# ---------------------------------------------------------------------------
# Code execution sandbox
# ---------------------------------------------------------------------------

class CodeSandbox:
    def __init__(self, engine: PredictionEngine):
        self.engine = engine
        self.global_ns = {
            "engine": self.engine,
            "borg_queen": self.engine.borg_queen,
            "last_data_model": lambda: self.engine.last_data_model,
            "last_result": lambda: self.engine.last_result,
            "time": time,
            "math": math if "math" in LOADED_LIBS else None,
            "numpy": LOADED_LIBS.get("numpy"),
            "pandas": LOADED_LIBS.get("pandas"),
        }

    def run_code(self, code: str) -> str:
        local_ns = {}
        try:
            exec(code, self.global_ns, local_ns)
            return "[CODE EXECUTED]\n" + repr(local_ns)
        except Exception as e:
            return "[ERROR]\n" + "".join(
                traceback.format_exception(type(e), e, e.__traceback__)
            )

# ---------------------------------------------------------------------------
# GUI (Tkinter with tabs + simple risk gauge + logs)
# ---------------------------------------------------------------------------

try:
    import tkinter as tk
    from tkinter import scrolledtext
    from tkinter import ttk
except ImportError:
    tk = None
    scrolledtext = None
    ttk = None
    print("[ERROR] tkinter not available. GUI will not start.")

class PredictionGUI:
    def __init__(self, engine: PredictionEngine, sandbox: CodeSandbox):
        if tk is None or ttk is None:
            raise RuntimeError("Tkinter not available.")

        self.engine = engine
        self.sandbox = sandbox
        self.root = tk.Tk()
        self.root.title("Global Prediction Borg v5")

        self.task_queue = queue.Queue()

        self._build_layout()
        self._start_worker_thread()
        self._start_status_updater()

    def _build_layout(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Console tab
        self.tab_console = tk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console")

        lbl_q = tk.Label(self.tab_console, text="Question / Prompt:")
        lbl_q.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.txt_question = scrolledtext.ScrolledText(self.tab_console, height=4, width=80)
        self.txt_question.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.use_borg_var = tk.BooleanVar(value=True)
        chk_borg = tk.Checkbutton(
            self.tab_console,
            text="Use Borg latest data (background workers)",
            variable=self.use_borg_var
        )
        chk_borg.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        btn_predict = tk.Button(self.tab_console, text="Run Prediction", command=self._on_predict)
        btn_predict.grid(row=2, column=1, sticky="e", padx=5, pady=5)

        lbl_out = tk.Label(self.tab_console, text="Output:")
        lbl_out.grid(row=3, column=0, sticky="w", padx=5, pady=5)

        self.txt_output = scrolledtext.ScrolledText(self.tab_console, height=10, width=80, state="normal")
        self.txt_output.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        # Simple risk gauge
        lbl_gauge = tk.Label(self.tab_console, text="Live Risk Gauge:")
        lbl_gauge.grid(row=5, column=0, sticky="w", padx=5, pady=5)

        self.risk_var = tk.StringVar(value="N/A")
        self.lbl_risk = tk.Label(self.tab_console, textvariable=self.risk_var, font=("Consolas", 12, "bold"))
        self.lbl_risk.grid(row=5, column=1, sticky="e", padx=5, pady=5)

        # Data tab
        self.tab_data = tk.Frame(self.notebook)
        self.notebook.add(self.tab_data, text="Data")

        lbl_features = tk.Label(self.tab_data, text="Latest Features:")
        lbl_features.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.txt_features = scrolledtext.ScrolledText(self.tab_data, height=10, width=80)
        self.txt_features.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        lbl_sources = tk.Label(self.tab_data, text="Latest Sources (including WebScan):")
        lbl_sources.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.txt_sources = scrolledtext.ScrolledText(self.tab_data, height=10, width=80)
        self.txt_sources.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        btn_refresh_data = tk.Button(self.tab_data, text="Refresh from Borg", command=self._on_refresh_data)
        btn_refresh_data.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        # History tab
        self.tab_history = tk.Frame(self.notebook)
        self.notebook.add(self.tab_history, text="History")

        lbl_hist = tk.Label(self.tab_history, text="Recent Predictions:")
        lbl_hist.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.txt_history = scrolledtext.ScrolledText(self.tab_history, height=20, width=80)
        self.txt_history.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        btn_refresh_hist = tk.Button(self.tab_history, text="Refresh History", command=self._on_refresh_history)
        btn_refresh_hist.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        # Logs tab
        self.tab_logs = tk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="Logs")

        lbl_logs = tk.Label(self.tab_logs, text="Recent Logs:")
        lbl_logs.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.txt_logs = scrolledtext.ScrolledText(self.tab_logs, height=20, width=80)
        self.txt_logs.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        btn_refresh_logs = tk.Button(self.tab_logs, text="Refresh Logs", command=self._on_refresh_logs)
        btn_refresh_logs.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        # Sandbox tab
        self.tab_sandbox = tk.Frame(self.notebook)
        self.notebook.add(self.tab_sandbox, text="Sandbox")

        lbl_code = tk.Label(self.tab_sandbox, text="Custom Python Code (uses `engine` / `borg_queen`):")
        lbl_code.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self.txt_code = scrolledtext.ScrolledText(self.tab_sandbox, height=12, width=80)
        self.txt_code.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        btn_code = tk.Button(self.tab_sandbox, text="Execute Code", command=self._on_execute_code)
        btn_code.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self.txt_code_output = scrolledtext.ScrolledText(self.tab_sandbox, height=10, width=80)
        self.txt_code_output.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def _start_worker_thread(self):
        t = threading.Thread(target=self._worker_loop, daemon=True)
        t.start()

    def _worker_loop(self):
        while True:
            try:
                task, payload = self.task_queue.get()
                if task == "predict":
                    question, use_borg = payload
                    result = self.engine.predict(question, use_borg=use_borg)
                    self._append_console_output(self._format_prediction(result))
                    self._update_data_tab(result)
                    self._update_history_tab()
                    self._update_risk_gauge(result)
                elif task == "code":
                    code = payload
                    out = self.sandbox.run_code(code)
                    self._append_code_output(out)
                elif task == "refresh_data":
                    dm = self.engine.get_latest_borg_data()
                    if dm is not None:
                        result_like = {
                            "features": dm.features,
                            "sources": dm.sources,
                        }
                        self._update_data_tab(result_like)
                        self._append_console_output("[INFO] Data refreshed from BorgQueen.\n")
                    else:
                        self._append_console_output("[WARN] No Borg data available yet.\n")
                elif task == "refresh_history":
                    self._update_history_tab()
                elif task == "refresh_logs":
                    self._update_logs_tab()
            except Exception as e:
                self._append_console_output("[WORKER ERROR]\n" + repr(e))

    def _start_status_updater(self):
        def update_status():
            dm = self.engine.get_latest_borg_data()
            if dm is not None:
                features = dm.features
                risk_score = self.engine.ml.compute_risk_score(features)
                interp = self.engine.ml.interpret_risk(risk_score)
                self._update_risk_gauge({"risk_score": risk_score, "interpretation": interp})
            self.root.after(5000, update_status)
        self.root.after(5000, update_status)

    def _on_predict(self):
        question = self.txt_question.get("1.0", tk.END).strip()
        if not question:
            question = "(no question provided)"
        use_borg = bool(self.use_borg_var.get())
        self._append_console_output("[TASK] Running prediction...\n")
        self.task_queue.put(("predict", (question, use_borg)))

    def _on_execute_code(self):
        code = self.txt_code.get("1.0", tk.END)
        self._append_code_output("[TASK] Executing custom code...\n")
        self.task_queue.put(("code", code))

    def _on_refresh_data(self):
        self.task_queue.put(("refresh_data", None))

    def _on_refresh_history(self):
        self.task_queue.put(("refresh_history", None))

    def _on_refresh_logs(self):
        self.task_queue.put(("refresh_logs", None))

    def _append_console_output(self, text: str):
        def _update():
            self.txt_output.insert(tk.END, text)
            self.txt_output.see(tk.END)
        self.root.after(0, _update)

    def _append_code_output(self, text: str):
        def _update():
            self.txt_code_output.insert(tk.END, text + "\n")
            self.txt_code_output.see(tk.END)
        self.root.after(0, _update)

    def _update_data_tab(self, result: dict):
        def _update():
            features = result.get("features", {})
            sources = result.get("sources", {})

            self.txt_features.delete("1.0", tk.END)
            self.txt_features.insert(tk.END, json.dumps(features, indent=2))

            self.txt_sources.delete("1.0", tk.END)
            self.txt_sources.insert(tk.END, json.dumps(sources, indent=2))
        self.root.after(0, _update)

    def _update_history_tab(self):
        def _update():
            rows = self.engine.persistence.fetch_recent_predictions(limit=20)
            self.txt_history.delete("1.0", tk.END)
            for ts, question, risk_score, interp in rows:
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                line = f"[{ts_str}] {risk_score:.2f} - {interp} | Q: {question}\n"
                self.txt_history.insert(tk.END, line)
            self.txt_history.see(tk.END)
        self.root.after(0, _update)

    def _update_logs_tab(self):
        def _update():
            rows = self.engine.persistence.fetch_recent_logs(limit=50)
            self.txt_logs.delete("1.0", tk.END)
            for ts, level, msg in rows:
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                line = f"[{ts_str}] {level}: {msg}\n"
                self.txt_logs.insert(tk.END, line)
            self.txt_logs.see(tk.END)
        self.root.after(0, _update)

    def _update_risk_gauge(self, result: dict):
        def _update():
            score = result.get("risk_score", None)
            interp = result.get("interpretation", "")
            if score is None:
                self.risk_var.set("N/A")
                return
            self.risk_var.set(f"{score:.2f} | {interp}")
        self.root.after(0, _update)

    def _format_prediction(self, result: dict) -> str:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result["timestamp"]))
        return (
            f"[PREDICTION @ {ts}]\n"
            f"Question: {result['question']}\n"
            f"Risk Score: {result['risk_score']:.2f}\n"
            f"Interpretation: {result['interpretation']}\n\n"
        )

    def run(self):
        self.root.mainloop()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    engine = PredictionEngine()
    sandbox = CodeSandbox(engine)

    if tk is None or ttk is None:
        print("[FATAL] Tkinter not available. Install it or run in an environment with GUI support.")
        sys.exit(1)

    gui = PredictionGUI(engine, sandbox)
    gui.run()

if __name__ == "__main__":
    main()
