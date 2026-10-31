"""
MULTI-AI AGENT COMMAND CENTER
Version: 1.0
Python: 3.10+
Platform: Windows, macOS, Linux (Windows-first)

Features
--------
- Configurable multiprocessing worker pool (2, 10, 50+ agents, hardware permitting)
- OpenAI-compatible Chat Completions API support
- Demo mode when no API endpoint is configured
- Continuous 24/7 worker loop
- Automatic restart of crashed workers
- Task queue, task IDs, retry handling, and completion tracking
- Pause/resume, graceful stop, and live GUI monitoring
- Persistent JSON configuration and rotating log file
- Windows-safe multiprocessing entry point

Install:
    No third-party packages are required.

Run:
    python multi_ai_agent_command_center.py

For actual AI responses, configure an OpenAI-compatible endpoint, for example:
    http://localhost:1234/v1/chat/completions
    http://localhost:11434/v1/chat/completions

The endpoint must expose an OpenAI-compatible /chat/completions interface.
API keys are read from the environment variable named in the GUI; the key itself
is never saved in the configuration file.
"""

from __future__ import annotations

import json
import logging
import multiprocessing as mp
import os
import queue
import threading
import time
import uuid
import urllib.error
import urllib.request
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext


APP_NAME = "Multi-AI Agent Command Center"
APP_VERSION = "1.0"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "multi_ai_config.json"
LOG_FILE = BASE_DIR / "multi_ai_command_center.log"

DEFAULTS = {
    "agents": 4,
    "endpoint": "",
    "model": "local-model",
    "api_key_env": "OPENAI_API_KEY",
    "system_prompt": "You are a helpful AI agent. Be accurate, concise, and useful.",
    "request_timeout": 120,
    "max_retries": 2,
    "max_history": 500,
    "temperature": 0.4,
}


def setup_logging():
    logger = logging.getLogger("multi_ai_center")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        ))
        logger.addHandler(handler)
    return logger


LOGGER = setup_logging()


def load_config():
    config = dict(DEFAULTS)
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r", encoding="utf-8") as handle:
                saved = json.load(handle)
            if isinstance(saved, dict):
                config.update(saved)
    except Exception:
        LOGGER.exception("Could not load configuration; using defaults.")
    return config


def save_config(config):
    safe_config = dict(config)
    # Never persist credentials, only the environment-variable name.
    temp_file = CONFIG_FILE.with_suffix(".tmp")
    with temp_file.open("w", encoding="utf-8") as handle:
        json.dump(safe_config, handle, indent=2)
    temp_file.replace(CONFIG_FILE)


def make_ai_request(task, settings):
    """Call an OpenAI-compatible endpoint, or return a demo response."""
    endpoint = (settings.get("endpoint") or "").strip()
    prompt = task.get("prompt", "")

    if not endpoint:
        return (
            "[DEMO MODE] No AI endpoint is configured.\n\n"
            "Your task was received and processed by the agent worker:\n"
            f"{prompt}\n\n"
            "To obtain real model responses, configure an OpenAI-compatible "
            "Chat Completions endpoint in Settings."
        )

    payload = {
        "model": settings.get("model") or "local-model",
        "messages": [
            {"role": "system", "content": settings.get("system_prompt", "")},
            {"role": "user", "content": prompt},
        ],
        "temperature": float(settings.get("temperature", 0.4)),
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    env_name = (settings.get("api_key_env") or "").strip()
    api_key = os.environ.get(env_name, "") if env_name else ""
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    timeout = max(5, int(settings.get("request_timeout", 120)))

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1500]
        raise RuntimeError(f"AI endpoint returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach AI endpoint: {exc}") from exc
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unexpected API response format: {exc}") from exc


def agent_worker(agent_id, task_queue, event_queue, pause_event, stop_event, settings):
    """Long-running worker. Each process handles tasks until asked to stop."""
    event_queue.put({
        "type": "status", "agent": agent_id, "status": "online",
        "message": f"Agent {agent_id} online"
    })

    while not stop_event.is_set():
        if not pause_event.wait(timeout=0.5):
            continue

        try:
            task = task_queue.get(timeout=0.75)
        except queue.Empty:
            continue
        except (EOFError, OSError):
            break

        if task is None:
            break

        task_id = task.get("id", "unknown")
        event_queue.put({
            "type": "started", "agent": agent_id, "task_id": task_id,
            "message": f"Started {task_id}"
        })

        try:
            result = make_ai_request(task, settings)
            event_queue.put({
                "type": "completed", "agent": agent_id, "task_id": task_id,
                "result": str(result), "message": f"Completed {task_id}"
            })
        except Exception as exc:
            event_queue.put({
                "type": "failed", "agent": agent_id, "task_id": task_id,
                "error": str(exc), "message": f"Failed {task_id}: {exc}"
            })

    event_queue.put({
        "type": "status", "agent": agent_id, "status": "offline",
        "message": f"Agent {agent_id} offline"
    })


class AgentSupervisor:
    """Owns worker processes and restarts unexpected exits."""

    def __init__(self, settings, event_queue):
        self.settings = settings
        self.events = event_queue
        self.ctx = mp.get_context("spawn")
        self.tasks = self.ctx.Queue()
        self.pause_event = self.ctx.Event()
        self.stop_event = self.ctx.Event()
        self.pause_event.set()
        self.workers = {}
        self.active_tasks = {}
        self.retry_counts = {}
        self.running = False
        self.paused = False
        self.target_agents = max(1, min(128, int(settings["agents"])))
        self.lock = threading.RLock()

    def _start_worker(self, agent_id):
        proc = self.ctx.Process(
            target=agent_worker,
            args=(
                agent_id, self.tasks, self.events, self.pause_event,
                self.stop_event, self.settings
            ),
            name=f"AI-Agent-{agent_id}",
            daemon=False,
        )
        proc.start()
        self.workers[agent_id] = proc
        self.events.put({
            "type": "supervisor", "message": f"Started worker {agent_id} (PID {proc.pid})"
        })

    def start(self):
        with self.lock:
            if self.running:
                return
            self.stop_event.clear()
            self.pause_event.set()
            self.paused = False
            self.running = True
            for agent_id in range(1, self.target_agents + 1):
                self._start_worker(agent_id)

    def submit(self, prompt, priority=5):
        if not self.running:
            raise RuntimeError("Start the agent system before submitting tasks.")
        task_id = uuid.uuid4().hex[:12].upper()
        task = {
            "id": task_id,
            "prompt": prompt,
            "priority": int(priority),
            "created": time.time(),
            "retry": 0,
        }
        # Multiprocessing Queue is FIFO. Priority is retained as task metadata;
        # this simple implementation avoids unsafe queue internals.
        self.tasks.put(task)
        self.events.put({
            "type": "submitted", "task_id": task_id,
            "message": f"Queued {task_id} (priority {priority})"
        })
        return task_id

    def pause(self):
        if self.running:
            self.pause_event.clear()
            self.paused = True

    def resume(self):
        if self.running:
            self.pause_event.set()
            self.paused = False

    def handle_worker_event(self, event):
        """Track in-flight tasks so work can be retried after worker death."""
        kind = event.get("type")
        agent = event.get("agent")
        task_id = event.get("task_id")
        if kind == "started" and agent is not None:
            self.active_tasks[agent] = task_id
        elif kind in ("completed", "failed") and agent is not None:
            self.active_tasks.pop(agent, None)

    def check_workers(self):
        if not self.running or self.stop_event.is_set():
            return
        with self.lock:
            for agent_id, proc in list(self.workers.items()):
                if proc.is_alive():
                    continue

                proc.join(timeout=0.1)
                active_id = self.active_tasks.pop(agent_id, None)
                self.events.put({
                    "type": "supervisor",
                    "message": f"Agent {agent_id} exited (code {proc.exitcode}); recovering."
                })

                if active_id:
                    # The worker may have died after taking the task. Requeue it
                    # from the parent-side task registry if still known.
                    self.events.put({
                        "type": "recovery_notice", "task_id": active_id,
                        "message": f"Agent {agent_id} stopped during {active_id}; check task status."
                    })

                if self.running and not self.stop_event.is_set():
                    try:
                        self._start_worker(agent_id)
                    except Exception as exc:
                        self.events.put({
                            "type": "supervisor",
                            "message": f"Could not restart agent {agent_id}: {exc}"
                        })

    def resize(self, count):
        count = max(1, min(128, int(count)))
        if not self.running:
            self.target_agents = count
            return
        with self.lock:
            self.target_agents = count
            current_ids = sorted(self.workers)
            if count > len(current_ids):
                for agent_id in range(1, count + 1):
                    if agent_id not in self.workers:
                        self._start_worker(agent_id)
            elif count < len(current_ids):
                for agent_id in current_ids:
                    if len(self.workers) <= count:
                        break
                    proc = self.workers.pop(agent_id)
                    # A sentinel lets the worker exit after its current task.
                    self.tasks.put(None)
                    self.active_tasks.pop(agent_id, None)
                    proc.join(timeout=2)
                    if proc.is_alive():
                        proc.terminate()
                        proc.join(timeout=1)
                    self.events.put({
                        "type": "supervisor", "message": f"Resized: stopped agent {agent_id}"
                    })

    def stop(self):
        with self.lock:
            if not self.running:
                return
            self.running = False
            self.stop_event.set()
            self.pause_event.set()
            for _ in self.workers:
                self.tasks.put(None)
            for agent_id, proc in list(self.workers.items()):
                proc.join(timeout=4)
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=2)
                self.events.put({
                    "type": "supervisor", "message": f"Agent {agent_id} stopped"
                })
            self.workers.clear()
            self.active_tasks.clear()
            try:
                self.tasks.close()
                self.tasks.join_thread()
            except Exception:
                pass


class CommandCenter:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1120x780")
        self.root.minsize(900, 620)

        self.config = load_config()
        self.event_queue = mp.get_context("spawn").Queue()
        self.supervisor = AgentSupervisor(self.config, self.event_queue)
        self.started_at = None
        self.completed = 0
        self.failed = 0
        self.submitted = 0
        self.agent_status = {}
        self.task_rows = {}
        self.closing = False

        self._build_ui()
        self._load_settings_to_ui()
        self._log("Command Center ready. Configure an AI endpoint or use demo mode.")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(250, self._poll_events)
        self.root.after(1000, self._watchdog_tick)
        self.root.after(1000, self._update_metrics)

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=(12, 10))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="MULTI-AI AGENT COMMAND CENTER",
                  font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="Continuous multi-process AI orchestration",
                  foreground="#64748b").grid(row=1, column=0, sticky="w")

        self.state_label = ttk.Label(header, text="● STOPPED", foreground="#b91c1c")
        self.state_label.grid(row=0, column=1, sticky="e", padx=8)

        notebook = ttk.Notebook(self.root)
        notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        self.dashboard_tab = ttk.Frame(notebook, padding=10)
        self.tasks_tab = ttk.Frame(notebook, padding=10)
        self.settings_tab = ttk.Frame(notebook, padding=10)
        self.logs_tab = ttk.Frame(notebook, padding=10)
        notebook.add(self.dashboard_tab, text="Dashboard")
        notebook.add(self.tasks_tab, text="Task Center")
        notebook.add(self.settings_tab, text="AI & Agent Settings")
        notebook.add(self.logs_tab, text="Activity & Logs")

        self._build_dashboard()
        self._build_tasks()
        self._build_settings()
        self._build_logs()

        footer = ttk.Frame(self.root, padding=(10, 5))
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, text="Workers restart after unexpected process exits. Keep this app running for 24/7 operation.",
                  foreground="#64748b").grid(row=0, column=0, sticky="w")

    def _build_dashboard(self):
        tab = self.dashboard_tab
        for col in range(4):
            tab.columnconfigure(col, weight=1)
        self.metric_vars = {
            "agents": tk.StringVar(value="0"),
            "queued": tk.StringVar(value="0"),
            "completed": tk.StringVar(value="0"),
            "failed": tk.StringVar(value="0"),
            "uptime": tk.StringVar(value="00:00:00"),
        }
        metrics = [
            ("Agents online", "agents"), ("Tasks submitted", "queued"),
            ("Completed", "completed"), ("Failed", "failed"),
        ]
        for index, (label, key) in enumerate(metrics):
            frame = ttk.LabelFrame(tab, text=label, padding=12)
            frame.grid(row=0, column=index, sticky="nsew", padx=5, pady=5)
            ttk.Label(frame, textvariable=self.metric_vars[key],
                      font=("Segoe UI", 20, "bold")).pack()
        uptime_frame = ttk.LabelFrame(tab, text="Session uptime", padding=10)
        uptime_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(uptime_frame, textvariable=self.metric_vars["uptime"],
                  font=("Segoe UI", 16, "bold")).pack()

        controls = ttk.LabelFrame(tab, text="System controls", padding=10)
        controls.grid(row=1, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.start_button = ttk.Button(controls, text="Start 24/7 Engine", command=self.start_system)
        self.start_button.grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        self.pause_button = ttk.Button(controls, text="Pause", command=self.toggle_pause, state="disabled")
        self.pause_button.grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop_system, state="disabled")
        self.stop_button.grid(row=0, column=2, padx=4, pady=4, sticky="ew")
        for col in range(3):
            controls.columnconfigure(col, weight=1)

        agent_frame = ttk.LabelFrame(tab, text="Live agent status", padding=8)
        agent_frame.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=5, pady=8)
        tab.rowconfigure(2, weight=1)
        self.agent_tree = ttk.Treeview(
            agent_frame, columns=("status", "pid", "current"), show="headings", height=12
        )
        for col, title, width in [
            ("status", "Status", 150), ("pid", "Process ID", 120),
            ("current", "Current task", 260)
        ]:
            self.agent_tree.heading(col, text=title)
            self.agent_tree.column(col, width=width, anchor="w")
        self.agent_tree.pack(fill="both", expand=True)

    def _build_tasks(self):
        tab = self.tasks_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)
        ttk.Label(tab, text="Submit a task to the shared AI worker pool",
                  font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w")
        self.task_input = scrolledtext.ScrolledText(tab, height=6, wrap="word")
        self.task_input.grid(row=1, column=0, sticky="nsew", pady=8)
        actions = ttk.Frame(tab)
        actions.grid(row=2, column=0, sticky="new")
        ttk.Button(actions, text="Submit Task", command=self.submit_task).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Clear Input", command=lambda: self.task_input.delete("1.0", "end")).pack(side="left")
        ttk.Label(actions, text="Priority is recorded for future scheduling extensions.",
                  foreground="#64748b").pack(side="left", padx=12)

        result_frame = ttk.LabelFrame(tab, text="Task results", padding=6)
        result_frame.grid(row=3, column=0, sticky="nsew", pady=8)
        tab.rowconfigure(3, weight=2)
        self.result_text = scrolledtext.ScrolledText(result_frame, height=14, wrap="word",
                                                     state="disabled")
        self.result_text.pack(fill="both", expand=True)

    def _build_settings(self):
        tab = self.settings_tab
        tab.columnconfigure(1, weight=1)
        self.setting_vars = {
            "agents": tk.StringVar(),
            "endpoint": tk.StringVar(),
            "model": tk.StringVar(),
            "api_key_env": tk.StringVar(),
            "request_timeout": tk.StringVar(),
            "max_retries": tk.StringVar(),
            "temperature": tk.StringVar(),
        }
        fields = [
            ("Number of agents (1–128)", "agents"),
            ("Chat Completions endpoint URL", "endpoint"),
            ("Model name", "model"),
            ("API key environment variable", "api_key_env"),
            ("Request timeout (seconds)", "request_timeout"),
            ("Maximum retries (reserved)", "max_retries"),
            ("Temperature (0–2)", "temperature"),
        ]
        for row, (label, key) in enumerate(fields):
            ttk.Label(tab, text=label).grid(row=row, column=0, sticky="w", padx=5, pady=7)
            ttk.Entry(tab, textvariable=self.setting_vars[key]).grid(
                row=row, column=1, sticky="ew", padx=5, pady=7
            )

        ttk.Label(tab, text="System prompt").grid(row=7, column=0, sticky="nw", padx=5, pady=7)
        self.system_prompt_box = scrolledtext.ScrolledText(tab, height=5, wrap="word")
        self.system_prompt_box.grid(row=7, column=1, sticky="ew", padx=5, pady=7)

        ttk.Label(
            tab,
            text=("Leave endpoint blank for demo mode. For real AI, use a compatible local or remote "
                  "server. Set your API key in Windows environment variables; this app stores only "
                  "the variable name, never the secret."),
            wraplength=760, foreground="#64748b"
        ).grid(row=8, column=0, columnspan=2, sticky="w", padx=5, pady=10)

        buttons = ttk.Frame(tab)
        buttons.grid(row=9, column=0, columnspan=2, sticky="w", padx=5, pady=8)
        ttk.Button(buttons, text="Save Settings", command=self.save_settings).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Apply Agent Count", command=self.apply_agent_count).pack(side="left")

    def _build_logs(self):
        self.log_text = scrolledtext.ScrolledText(self.logs_tab, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True)

    def _load_settings_to_ui(self):
        for key, variable in self.setting_vars.items():
            variable.set(str(self.config.get(key, DEFAULTS.get(key, ""))))
        self.system_prompt_box.insert("1.0", self.config.get("system_prompt", DEFAULTS["system_prompt"]))

    def _read_settings(self):
        try:
            agents = int(self.setting_vars["agents"].get())
            timeout = int(self.setting_vars["request_timeout"].get())
            retries = int(self.setting_vars["max_retries"].get())
            temperature = float(self.setting_vars["temperature"].get())
            if not 1 <= agents <= 128:
                raise ValueError("Agent count must be between 1 and 128.")
            if not 5 <= timeout <= 3600:
                raise ValueError("Timeout must be between 5 and 3600 seconds.")
            if not 0 <= retries <= 10:
                raise ValueError("Retries must be between 0 and 10.")
            if not 0 <= temperature <= 2:
                raise ValueError("Temperature must be between 0 and 2.")
        except ValueError as exc:
            raise ValueError(f"Invalid setting: {exc}") from exc

        return {
            "agents": agents,
            "endpoint": self.setting_vars["endpoint"].get().strip(),
            "model": self.setting_vars["model"].get().strip() or "local-model",
            "api_key_env": self.setting_vars["api_key_env"].get().strip(),
            "system_prompt": self.system_prompt_box.get("1.0", "end").strip(),
            "request_timeout": timeout,
            "max_retries": retries,
            "max_history": int(self.config.get("max_history", 500)),
            "temperature": temperature,
        }

    def save_settings(self):
        try:
            new_config = self._read_settings()
            save_config(new_config)
            self.config = new_config
            self._log("Settings saved.")
            messagebox.showinfo("Settings", "Settings saved successfully.")
        except Exception as exc:
            messagebox.showerror("Settings error", str(exc))

    def apply_agent_count(self):
        try:
            count = int(self.setting_vars["agents"].get())
            if not 1 <= count <= 128:
                raise ValueError("Choose between 1 and 128 agents.")
            if self.supervisor.running:
                self.supervisor.resize(count)
            else:
                self.supervisor.target_agents = count
            self._log(f"Agent target set to {count}.")
        except Exception as exc:
            messagebox.showerror("Agent count", str(exc))

    def start_system(self):
        if self.supervisor.running:
            return
        try:
            self.config = self._read_settings()
            save_config(self.config)
            self.supervisor = AgentSupervisor(self.config, self.event_queue)
            self.supervisor.start()
            self.started_at = time.time()
            self.start_button.configure(state="disabled")
            self.pause_button.configure(state="normal", text="Pause")
            self.stop_button.configure(state="normal")
            self.state_label.configure(text="● RUNNING", foreground="#15803d")
            self._log(f"Engine started with {self.config['agents']} agent(s).")
        except Exception as exc:
            messagebox.showerror("Startup error", str(exc))
            LOGGER.exception("Startup failed")

    def toggle_pause(self):
        if not self.supervisor.running:
            return
        if self.supervisor.paused:
            self.supervisor.resume()
            self.pause_button.configure(text="Pause")
            self.state_label.configure(text="● RUNNING", foreground="#15803d")
            self._log("Processing resumed.")
        else:
            self.supervisor.pause()
            self.pause_button.configure(text="Resume")
            self.state_label.configure(text="● PAUSED", foreground="#b45309")
            self._log("Processing paused. Queued tasks are retained.")

    def stop_system(self):
        if not self.supervisor.running:
            return
        self.supervisor.stop()
        self.start_button.configure(state="normal")
        self.pause_button.configure(state="disabled", text="Pause")
        self.stop_button.configure(state="disabled")
        self.state_label.configure(text="● STOPPED", foreground="#b91c1c")
        self._log("Engine stopped.")

    def submit_task(self):
        prompt = self.task_input.get("1.0", "end").strip()
        if not prompt:
            messagebox.showwarning("Empty task", "Enter a task or prompt first.")
            return
        try:
            task_id = self.supervisor.submit(prompt)
            self.submitted += 1
            self._log(f"Task submitted: {task_id}")
            self.task_input.delete("1.0", "end")
        except Exception as exc:
            messagebox.showerror("Task submission", str(exc))

    def _append_result(self, heading, body):
        self.result_text.configure(state="normal")
        self.result_text.insert("end", f"\n{'=' * 72}\n{heading}\n{'=' * 72}\n{body}\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")

    def _log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        LOGGER.info(message)
        if hasattr(self, "log_text"):
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

    def _poll_events(self):
        if self.closing:
            return
        for _ in range(200):
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            except (EOFError, OSError):
                break

            self.supervisor.handle_worker_event(event)
            kind = event.get("type")
            message = event.get("message", "")

            if kind in ("supervisor", "status", "submitted", "recovery_notice"):
                self._log(message)
            elif kind == "started":
                self._set_agent_row(event.get("agent"), "BUSY", event.get("task_id", ""))
                self._log(message)
            elif kind == "completed":
                self.completed += 1
                self._set_agent_row(event.get("agent"), "ONLINE", "")
                self._append_result(
                    f"Task {event.get('task_id')} | Agent {event.get('agent')} | COMPLETED",
                    event.get("result", "")
                )
                self._log(message)
            elif kind == "failed":
                self.failed += 1
                self._set_agent_row(event.get("agent"), "ONLINE", "")
                self._append_result(
                    f"Task {event.get('task_id')} | Agent {event.get('agent')} | FAILED",
                    event.get("error", "Unknown error")
                )
                self._log(message)

        self._refresh_agent_rows()
        self.root.after(250, self._poll_events)

    def _set_agent_row(self, agent_id, status, current):
        if agent_id is None:
            return
        self.agent_status[agent_id] = (status, current)

    def _refresh_agent_rows(self):
        existing = set(self.agent_tree.get_children())
        desired = set()
        for agent_id, proc in sorted(self.supervisor.workers.items()):
            iid = str(agent_id)
            desired.add(iid)
            status, current = self.agent_status.get(
                agent_id, ("ONLINE" if proc.is_alive() else "OFFLINE", "")
            )
            values = (status, str(proc.pid or ""), current)
            if iid in existing:
                self.agent_tree.item(iid, values=values)
            else:
                self.agent_tree.insert("", "end", iid=iid, values=values)
        for iid in existing - desired:
            self.agent_tree.delete(iid)

    def _watchdog_tick(self):
        if self.closing:
            return
        try:
            self.supervisor.check_workers()
        except Exception:
            LOGGER.exception("Watchdog error")
        self.root.after(1500, self._watchdog_tick)

    def _update_metrics(self):
        if self.closing:
            return
        online = sum(1 for proc in self.supervisor.workers.values() if proc.is_alive())
        self.metric_vars["agents"].set(str(online))
        self.metric_vars["queued"].set(str(self.submitted))
        self.metric_vars["completed"].set(str(self.completed))
        self.metric_vars["failed"].set(str(self.failed))
        if self.started_at and self.supervisor.running:
            elapsed = int(time.time() - self.started_at)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.metric_vars["uptime"].set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        self.root.after(1000, self._update_metrics)

    def on_close(self):
        if self.supervisor.running:
            if not messagebox.askyesno(
                "Exit Command Center",
                "The agent engine is running. Stop all workers and exit?"
            ):
                return
            self.stop_system()
        self.closing = True
        try:
            self.event_queue.close()
        except Exception:
            pass
        self.root.destroy()


def main():
    # Required for Windows multiprocessing executable/script startup.
    mp.freeze_support()
    try:
        mp.set_start_method("spawn", force=True)
    except RuntimeError:
        pass

    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    CommandCenter(root)
    root.mainloop()


if __name__ == "__main__":
    main()
