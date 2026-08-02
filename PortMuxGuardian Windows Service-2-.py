#!/usr/bin/env python3
# codex_security_bridge_v2.py
# 3 stacks + AI controller + autoloader + HTTP bridge

import sys
import subprocess
import importlib
import threading
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from typing import Optional, Dict, Any

# ============================================================
# LOGGING
# ============================================================

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{ts}] {msg}")

# ============================================================
# AUTOLOADER (GROUP-BASED)
# ============================================================

class Autoloader:
    def __init__(self) -> None:
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "notify": {"modules": ["win10toast"], "install": True},
            "network": {"modules": ["requests"], "install": True},
        }
        self.loaded_modules: Dict[str, Any] = {}
        self.lock = threading.Lock()

    def _soft_import(self, name: str) -> Optional[Any]:
        try:
            return importlib.import_module(name)
        except ImportError:
            return None

    def _install(self, name: str) -> bool:
        try:
            log(f"[AUTOLOADER] Installing {name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", name])
            return True
        except Exception as e:
            log(f"[AUTOLOADER] Install failed for {name}: {e}")
            return False

    def ensure_group(self, group: str) -> None:
        cfg = self.dependency_map.get(group, {})
        mods = cfg.get("modules", [])
        allow_install = cfg.get("install", False)
        for m in mods:
            mod = self._soft_import(m)
            if mod is None and allow_install and self._install(m):
                mod = self._soft_import(m)
            if mod is not None:
                with self.lock:
                    self.loaded_modules[m] = mod

    def get(self, name: str) -> Optional[Any]:
        with self.lock:
            return self.loaded_modules.get(name)

AUTOLOADER = Autoloader()
AUTOLOADER.ensure_group("notify")
AUTOLOADER.ensure_group("network")

# ============================================================
# STACKS
# ============================================================

@dataclass
class StackStatus:
    events: int = 0
    last_event: Optional[str] = None

class BaseStack:
    def __init__(self, label: str) -> None:
        self.label = label
        self.status = StackStatus()
        self.lock = threading.Lock()

    def handle(self, payload: str) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[{self.label}] {payload}")

    def get_status(self) -> StackStatus:
        with self.lock:
            return StackStatus(self.status.events, self.status.last_event)

class SecurityStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("SEC")

class GamingStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("GAME")

class HighRiskStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("HRISK")

# ============================================================
# AI CONTROLLER
# ============================================================

class AIController:
    def __init__(self,
                 sec: SecurityStack,
                 game: GamingStack,
                 hrisk: HighRiskStack) -> None:
        self.sec = sec
        self.game = game
        self.hrisk = hrisk
        self.mode = "balanced"
        self.running = False
        self.lock = threading.Lock()

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[AI] Controller started")

    def stop(self) -> None:
        self.running = False
        log("[AI] Controller stopped")

    def _loop(self) -> None:
        while self.running:
            time.sleep(1.0)

            sec_s = self.sec.get_status()
            game_s = self.game.get_status()
            hrisk_s = self.hrisk.get_status()

            sec_events = sec_s.events
            game_events = game_s.events
            hrisk_events = hrisk_s.events

            if hrisk_events > 20 and hrisk_events >= sec_events:
                mode = "highrisk_lockdown"
            elif sec_events > 50 and sec_events > 2 * game_events:
                mode = "security_priority"
            elif game_events > 50 and game_events > 2 * sec_events:
                mode = "gaming_priority"
            else:
                mode = "balanced"

            with self.lock:
                self.mode = mode

            log(f"[AI] mode={mode} sec={sec_events} game={game_events} hrisk={hrisk_events}")

    def get_mode(self) -> str:
        with self.lock:
            return self.mode

# ============================================================
# NOTIFICATIONS (OPTIONAL)
# ============================================================

class Notifier:
    def __init__(self) -> None:
        win10toast = AUTOLOADER.get("win10toast")
        if win10toast:
            self.toaster = win10toast.ToastNotifier()
        else:
            self.toaster = None
            log("[NOTIFY] win10toast not available")

    def notify(self, title: str, msg: str) -> None:
        if self.toaster:
            self.toaster.show_toast(title, msg, duration=5, threaded=True)
        log(f"[NOTIFY] {title} -> {msg}")

# ============================================================
# HTTP BRIDGE
# ============================================================

class BridgeHandler(BaseHTTPRequestHandler):
    supervisor = None  # type: ignore

    def _send_json(self, obj: Dict[str, Any], code: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8", errors="ignore"))
        except Exception:
            payload = {}

        kind = payload.get("kind")
        value = payload.get("value")

        # Map both explicit stack kinds and your extension kinds
        if kind in ("security", "url"):
            self.supervisor.handle_security(str(value))
            self._send_json({"ok": True, "stack": "security"})
        elif kind in ("gaming", "query"):
            self.supervisor.handle_gaming(str(value))
            self._send_json({"ok": True, "stack": "gaming"})
        elif kind in ("highrisk", "ai_text"):
            self.supervisor.handle_highrisk(str(value))
            self._send_json({"ok": True, "stack": "highrisk"})
        else:
            self._send_json({"error": "unknown kind"}, 400)

    def do_GET(self) -> None:
        if self.path == "/status":
            self._send_json(self.supervisor.get_status())
        elif self.path == "/ai":
            self._send_json({"mode": self.supervisor.ai.get_mode()})
        else:
            self._send_json({"error": "not found"}, 404)

    def log_message(self, format: str, *args: Any) -> None:
        pass

class BridgeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, supervisor: "Supervisor" = None) -> None:
        self.host = host
        self.port = port
        self.supervisor = supervisor
        self.httpd: Optional[HTTPServer] = None

    def start(self) -> None:
        BridgeHandler.supervisor = self.supervisor
        self.httpd = HTTPServer((self.host, self.port), BridgeHandler)
        log(f"[BRIDGE] Listening on http://{self.host}:{self.port}/bridge")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        log("[BRIDGE] Stopped")

# ============================================================
# SUPERVISOR
# ============================================================

class Supervisor:
    def __init__(self) -> None:
        self.sec = SecurityStack()
        self.game = GamingStack()
        self.hrisk = HighRiskStack()
        self.ai = AIController(self.sec, self.game, self.hrisk)
        self.bridge = BridgeServer(supervisor=self)
        self.notifier = Notifier()
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        log("[SUP] Starting Codex Security Bridge v2")
        self.ai.start()
        self.bridge.start()
        log("[SUP] All subsystems started")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        log("[SUP] Stopping subsystems")
        self.ai.stop()
        self.bridge.stop()
        log("[SUP] All subsystems stopped")

    # Bridge handlers
    def handle_security(self, payload: str) -> None:
        self.sec.handle(payload)
        if self.ai.get_mode() in ("security_priority", "highrisk_lockdown"):
            self.notifier.notify("Security event", payload)

    def handle_gaming(self, payload: str) -> None:
        self.game.handle(payload)

    def handle_highrisk(self, payload: str) -> None:
        self.hrisk.handle(payload)
        if self.ai.get_mode() == "highrisk_lockdown":
            self.notifier.notify("High-risk activity", payload)

    def get_status(self) -> Dict[str, Any]:
        sec = self.sec.get_status()
        game = self.game.get_status()
        hrisk = self.hrisk.get_status()
        return {
            "running": self.running,
            "mode": self.ai.get_mode(),
            "security": {"events": sec.events, "last_event": sec.last_event},
            "gaming": {"events": game.events, "last_event": game.last_event},
            "highrisk": {"events": hrisk.events, "last_event": hrisk.last_event},
        }

# ============================================================
# MAIN
# ============================================================

def main() -> None:
    sup = Supervisor()
    sup.start()
    log("[MAIN] Codex Security Bridge v2 running. Ctrl+C to exit.")
    try:
        while True:
            time.sleep(3.0)
            status = sup.get_status()
            log(f"[STATUS] {status}")
    except KeyboardInterrupt:
        log("[MAIN] Ctrl+C detected, stopping.")
        sup.stop()

if __name__ == "__main__":
    main()
