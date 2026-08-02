#!/usr/bin/env python3
# codex_security_bridge_v1.py
# Headless autonomous AI security/gaming/high-risk daemon
# - Runs local HTTP bridge (/bridge)
# - Accepts JSON events: {kind: "security"|"gaming"|"highrisk", value: "..."}
# - Feeds three stacks
# - AI controller decides mode (balanced / security_priority / gaming_priority / highrisk_lockdown)
# - Logs everything to console
# - No GUI, no Windows service wrapper

import sys
import threading
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

# ============================================================
# LOGGING
# ============================================================

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{ts}] {msg}")

# ============================================================
# STACKS
# ============================================================

@dataclass
class StackStatus:
    events: int = 0
    last_event: Optional[str] = None

class SecurityStack:
    def __init__(self) -> None:
        self.status = StackStatus()
        self.lock = threading.Lock()

    def handle(self, payload: str) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[SEC] {payload}")

    def get_status(self) -> StackStatus:
        with self.lock:
            return StackStatus(self.status.events, self.status.last_event)

class GamingStack:
    def __init__(self) -> None:
        self.status = StackStatus()
        self.lock = threading.Lock()

    def handle(self, payload: str) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[GAME] {payload}")

    def get_status(self) -> StackStatus:
        with self.lock:
            return StackStatus(self.status.events, self.status.last_event)

class HighRiskStack:
    def __init__(self) -> None:
        self.status = StackStatus()
        self.lock = threading.Lock()

    def handle(self, payload: str) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[HRISK] {payload}")

    def get_status(self) -> StackStatus:
        with self.lock:
            return StackStatus(self.status.events, self.status.last_event)

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
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log("[AI] Controller started")

    def stop(self) -> None:
        self.running = False
        log("[AI] Controller stopped")

    def _loop(self) -> None:
        while self.running:
            time.sleep(1.0)

            sec_status = self.sec.get_status()
            game_status = self.game.get_status()
            hrisk_status = self.hrisk.get_status()

            sec_events = sec_status.events
            game_events = game_status.events
            hrisk_events = hrisk_status.events

            if hrisk_events > 50 and hrisk_events > sec_events:
                mode = "highrisk_lockdown"
            elif sec_events > 100 and sec_events > 2 * game_events:
                mode = "security_priority"
            elif game_events > 100 and game_events > 2 * sec_events:
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

        if kind == "security":
            self.supervisor.handle_security(value)
            self._send_json({"ok": True, "stack": "security"})
        elif kind == "gaming":
            self.supervisor.handle_gaming(value)
            self._send_json({"ok": True, "stack": "gaming"})
        elif kind == "highrisk":
            self.supervisor.handle_highrisk(value)
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
        # Silence default HTTP logging
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

        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()

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
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        log("[SUP] Starting Codex Security Bridge v1")
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

    # Handlers used by BridgeHandler
    def handle_security(self, payload: Any) -> None:
        if isinstance(payload, str):
            self.sec.handle(payload)

    def handle_gaming(self, payload: Any) -> None:
        if isinstance(payload, str):
            self.game.handle(payload)

    def handle_highrisk(self, payload: Any) -> None:
        if isinstance(payload, str):
            self.hrisk.handle(payload)

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
    log("[MAIN] Codex Security Bridge running. Ctrl+C to exit.")
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
