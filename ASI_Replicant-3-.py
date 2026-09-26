import sys
import threading
import time
import socket
import os
import struct
import ctypes
import subprocess
from collections import defaultdict

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout
from PyQt5.QtCore import Qt, pyqtSignal, QObject

# =========================
# AUTOLOADER
# =========================
def autoload(libs):
    for lib in libs:
        try:
            __import__(lib)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

autoload(["PyQt5", "pydivert"])

# GPU is optional; if it fails, we just run CPU scoring.
try:
    autoload(["cupy"])
    import cupy as cp
    GPU_AVAILABLE = True
except Exception:
    GPU_AVAILABLE = False

from pydivert import WinDivert

# =========================
# AUTO-ELEVATION (Windows)
# =========================
def ensure_admin():
    if "--elevated" in sys.argv:
        return

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        params = " ".join([f'"{arg}"' for arg in sys.argv] + ["--elevated"])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit()

if os.name == "nt":
    ensure_admin()

# =========================
# CONFIG
# =========================
LOCAL_SUBNET_PREFIXES = [
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
]

TELEMETRY_INTERVAL_SEC = 10
FLOW_REPORT_INTERVAL_SEC = 15
TOP_FLOW_COUNT = 8

ENFORCE_BLOCKS = False          # Safe default: no blocking
BLOCK_SCORE_THRESHOLD = 80      # Score above this is considered block-worthy

# =========================
# LOG BUS (Thread-safe)
# =========================
class LogBus(QObject):
    threat_signal = pyqtSignal(str)
    lineage_signal = pyqtSignal(str)
    swarm_signal = pyqtSignal(str)

    def __init__(self, console):
        super().__init__()
        self.console = console
        self.threat_signal.connect(self.console.log_threat)
        self.lineage_signal.connect(self.console.log_lineage)
        self.swarm_signal.connect(self.console.log_swarm)

    def threat(self, msg: str):
        self.threat_signal.emit(msg)

    def lineage(self, msg: str):
        self.lineage_signal.emit(msg)

    def swarm(self, msg: str):
        self.swarm_signal.emit(msg)

# =========================
# GUI CONSOLE
# =========================
class ASIConsole(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ASI Sentinel Console")
        self.setGeometry(100, 100, 1200, 850)

        layout = QVBoxLayout()

        self.threatMatrix = QTextEdit()
        self.threatMatrix.setReadOnly(True)
        self.threatMatrix.setStyleSheet("background-color: #111; color: #0f0; font-family: Courier;")
        layout.addWidget(QLabel("Threat Matrix"))
        layout.addWidget(self.threatMatrix)

        self.lineageGraph = QTextEdit()
        self.lineageGraph.setReadOnly(True)
        self.lineageGraph.setStyleSheet("background-color: #111; color: #0ff; font-family: Courier;")
        layout.addWidget(QLabel("Capsule Lineage Graph"))
        layout.addWidget(self.lineageGraph)

        self.swarmSync = QTextEdit()
        self.swarmSync.setReadOnly(True)
        self.swarmSync.setStyleSheet("background-color: #111; color: #f0f; font-family: Courier;")
        layout.addWidget(QLabel("Swarm Sync Overlay"))
        layout.addWidget(self.swarmSync)

        btn_layout = QHBoxLayout()
        self.btn_quit = QPushButton("Terminate Swarm")
        self.btn_quit.clicked.connect(self.handle_quit)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_quit)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self._stop_flag = False

    def log_threat(self, msg):
        self.threatMatrix.append(msg)

    def log_lineage(self, msg):
        self.lineageGraph.append(msg)

    def log_swarm(self, msg):
        self.swarmSync.append(msg)

    def handle_quit(self):
        self._stop_flag = True
        self.log_swarm("[CONTROL] Termination signal issued.")
        QApplication.instance().quit()

    def stop_requested(self) -> bool:
        return self._stop_flag

# =========================
# UTILS
# =========================
def is_local_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in LOCAL_SUBNET_PREFIXES)

# =========================
# FLOW + THREAT ENGINE
# =========================
class FlowTable:
    """
    Aggregates flows by (src, dst, proto, sport, dport) with counters and threat scoring.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._flows = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "external": False,
            "last_seen": 0.0,
            "score": 0,
            "tags": set()
        })

    def update(self, key, length: int, external: bool, tags=None):
        if tags is None:
            tags = set()
        with self._lock:
            entry = self._flows[key]
            entry["packets"] += 1
            entry["bytes"] += max(length, 0)
            entry["external"] = entry["external"] or external
            entry["last_seen"] = time.time()
            entry["tags"].update(tags)

    def snapshot_top(self, limit: int = TOP_FLOW_COUNT):
        with self._lock:
            items = list(self._flows.items())
        items.sort(key=lambda kv: kv[1]["bytes"], reverse=True)
        return items[:limit]

    def snapshot_all(self):
        with self._lock:
            return dict(self._flows)

    def set_score(self, key, score: int):
        with self._lock:
            if key in self._flows:
                self._flows[key]["score"] = score

class ThreatEngine:
    """
    Computes threat scores for flows, optionally using GPU.
    """
    def __init__(self, flow_table: FlowTable):
        self.flow_table = flow_table

    def compute_scores(self):
        flows = self.flow_table.snapshot_all()
        keys = list(flows.keys())
        if not keys:
            return

        # CPU scoring baseline
        scores = []
        for key in keys:
            src, dst, proto, sport, dport = key
            f = flows[key]
            score = 0

            # External origin baseline
            if f["external"]:
                score += 30

            # High byte volume
            if f["bytes"] > 10_000_000:
                score += 30
            elif f["bytes"] > 1_000_000:
                score += 15

            # Suspicious ports
            if dport in (53, 80, 443):
                score += 5
            if dport not in (53, 80, 443, 22, 25, 110, 143):
                score += 10

            # Tags from DPI
            tags = f["tags"]
            if "dns_suspicious" in tags:
                score += 20
            if "http_suspicious" in tags:
                score += 20
            if "tls_sni_suspicious" in tags:
                score += 25

            # Age weighting
            age = time.time() - f["last_seen"]
            if age < 30:
                score += 10

            scores.append(score)

        # Optional GPU refinement (simple normalization)
        if GPU_AVAILABLE and scores:
            try:
                arr = cp.array(scores, dtype=cp.float32)
                max_val = float(cp.max(arr)) or 1.0
                arr = (arr / max_val) * 100.0
                scores = [int(float(v)) for v in arr.get()]
            except Exception:
                # If GPU fails, keep CPU scores
                pass

        # Write back
        for key, score in zip(keys, scores):
            self.flow_table.set_score(key, score)

    def risk_level(self, score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"

# =========================
# DPI HELPERS
# =========================
def parse_dns_query(payload: bytes):
    # Very basic DNS parser: header (12 bytes) + QNAME
    if len(payload) < 12:
        return None
    try:
        qname = []
        idx = 12
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                break
            idx += 1
            label = payload[idx:idx+length]
            qname.append(label.decode("ascii", errors="ignore"))
            idx += length
        if qname:
            return ".".join(qname)
    except Exception:
        return None
    return None

def parse_http_request(payload: bytes):
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return None, None
    lines = text.split("\r\n")
    if not lines:
        return None, None
    request_line = lines[0]
    if not any(request_line.startswith(m) for m in ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")):
        return None, None
    host = None
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return request_line, host

def parse_tls_sni(payload: bytes):
    # Very rough TLS ClientHello SNI extraction; not robust, but enough for basic telemetry.
    try:
        if len(payload) < 5:
            return None
        # TLS record header
        content_type = payload[0]
        if content_type != 0x16:  # Handshake
            return None
        # Skip record header (5 bytes), then handshake header (4 bytes)
        idx = 5 + 4
        if idx >= len(payload):
            return None
        # Skip client version + random (2 + 32)
        idx += 34
        if idx >= len(payload):
            return None
        # Session ID
        sid_len = payload[idx]
        idx += 1 + sid_len
        if idx >= len(payload):
            return None
        # Cipher suites
        cs_len = struct.unpack("!H", payload[idx:idx+2])[0]
        idx += 2 + cs_len
        if idx >= len(payload):
            return None
        # Compression methods
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx >= len(payload):
            return None
        # Extensions length
        ext_len = struct.unpack("!H", payload[idx:idx+2])[0]
        idx += 2
        end = idx + ext_len
        while idx + 4 <= end:
            ext_type = struct.unpack("!H", payload[idx:idx+2])[0]
            ext_size = struct.unpack("!H", payload[idx+2:idx+4])[0]
            idx += 4
            if ext_type == 0x00:  # SNI
                # SNI extension: list length (2), then name type (1), name length (2), then name
                if idx + 5 > len(payload):
                    return None
                list_len = struct.unpack("!H", payload[idx:idx+2])[0]
                idx += 2
                if idx + list_len > len(payload):
                    return None
                name_type = payload[idx]
                if name_type != 0:  # host_name
                    return None
                idx += 1
                name_len = struct.unpack("!H", payload[idx:idx+2])[0]
                idx += 2
                if idx + name_len > len(payload):
                    return None
                sni = payload[idx:idx+name_len].decode("ascii", errors="ignore")
                return sni
            else:
                idx += ext_size
        return None
    except Exception:
        return None

def inspect_packet(packet, flow_table: FlowTable, logbus: LogBus):
    """
    DPI: DNS, HTTP, TLS SNI, suspicious payload tagging.
    """
    raw = packet.raw
    length = len(raw)
    src = str(packet.src_addr)
    dst = str(packet.dst_addr)
    proto = packet.protocol
    sport = packet.src_port
    dport = packet.dst_port

    external = not is_local_ip(src)
    tags = set()

    # DNS
    if dport == 53 or sport == 53:
        qname = parse_dns_query(raw[packet.payload_offset:])
        if qname:
            logbus.lineage(f"[DNS] {src} → {dst} query: {qname}")
            if len(qname) > 50 or qname.count(".") > 5:
                tags.add("dns_suspicious")
                logbus.threat(f"[DNS-SUSPICIOUS] {qname} from {src}")

    # HTTP
    if dport == 80 or sport == 80:
        req_line, host = parse_http_request(raw[packet.payload_offset:])
        if req_line:
            logbus.lineage(f"[HTTP] {src} → {dst} {req_line} Host={host}")
            if host and any(t in host.lower() for t in ("tor", "onion", "dark", "proxy")):
                tags.add("http_suspicious")
                logbus.threat(f"[HTTP-SUSPICIOUS] Host={host} from {src}")

    # TLS SNI
    if dport == 443 or sport == 443:
        sni = parse_tls_sni(raw[packet.payload_offset:])
        if sni:
            logbus.lineage(f"[TLS] {src} → {dst} SNI={sni}")
            if any(t in sni.lower() for t in ("tor", "onion", "dark", "proxy")):
                tags.add("tls_sni_suspicious")
                logbus.threat(f"[TLS-SNI-SUSPICIOUS] SNI={sni} from {src}")

    key = (src, dst, proto, sport, dport)
    flow_table.update(key, length, external, tags)

# =========================
# WIN_DIVERT PACKET CAPTURE + ENFORCEMENT
# =========================
def divert_sniffer(console: ASIConsole, logbus: LogBus, flow_table: FlowTable, engine: ThreatEngine):
    """
    WinDivert-based packet capture with DPI, flow aggregation, threat scoring, and optional enforcement.
    """

    logbus.threat("[INIT] WinDivert sniffer starting...")

    filter_str = "true"  # Capture all IPv4 packets; refine later if desired.

    try:
        divert = WinDivert(filter_str)
        divert.open()
        logbus.threat("[INFO] WinDivert driver loaded successfully.")
    except Exception as e:
        logbus.threat(f"[ERROR] Failed to initialize WinDivert: {e}")
        return

    last_report = time.time()
    last_score_update = time.time()

    while not console.stop_requested():
        try:
            packet = divert.recv()
            if packet is None:
                continue

            src = str(packet.src_addr)
            dst = str(packet.dst_addr)
            length = len(packet.raw)

            logbus.threat(f"[FLOW] {src} → {dst} ({length} bytes)")
            inspect_packet(packet, flow_table, logbus)

            now = time.time()

            # Periodic scoring
            if now - last_score_update >= 5:
                last_score_update = now
                engine.compute_scores()

            # Enforcement decision
            key = (src, dst, packet.protocol, packet.src_port, packet.dst_port)
            flows = flow_table.snapshot_all()
            entry = flows.get(key)
            score = entry["score"] if entry else 0
            risk = engine.risk_level(score)

            if ENFORCE_BLOCKS and score >= BLOCK_SCORE_THRESHOLD:
                logbus.threat(f"[BLOCK] {risk} flow {src} → {dst} score={score} (packet dropped)")
                # Do NOT re-inject: packet is dropped.
            else:
                # Re-inject packet to keep traffic flowing.
                divert.send(packet)
                if score > 0:
                    logbus.swarm(f"[RISK] {risk} {src} → {dst} score={score}")

            # Periodic flow report
            if now - last_report >= FLOW_REPORT_INTERVAL_SEC:
                last_report = now
                report_flows(flow_table, logbus, engine)

        except Exception as e:
            logbus.threat(f"[ERROR] WinDivert recv/send failed: {e}")
            break

    try:
        divert.close()
        logbus.threat("[SHUTDOWN] WinDivert sniffer closed.")
    except Exception:
        pass

def report_flows(flow_table: FlowTable, logbus: LogBus, engine: ThreatEngine):
    top = flow_table.snapshot_top()
    if not top:
        logbus.swarm("[FLOWS] No active flows to report.")
        return

    logbus.swarm("[FLOWS] Top flows by byte volume:")
    for key, stats in top:
        src, dst, proto, sport, dport = key
        pkts = stats["packets"]
        bytes_ = stats["bytes"]
        external = stats["external"]
        score = stats["score"]
        risk = engine.risk_level(score)
        threat_tag = "EXTERNAL" if external else "LOCAL"
        logbus.swarm(
            f"  [{risk}/{threat_tag}] {src}:{sport} → {dst}:{dport} | pkts={pkts}, bytes={bytes_}, score={score}"
        )

# =========================
# TELEMETRY + MUTATION
# =========================
def telemetry_loop(console: ASIConsole, logbus: LogBus, flow_table: FlowTable, engine: ThreatEngine):
    logbus.swarm("[INIT] Telemetry loop online.")
    while not console.stop_requested():
        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
        logbus.swarm(f"[TELEMETRY] System load snapshot: {load:.2f}")

        flows = flow_table.snapshot_top(limit=3)
        if flows:
            logbus.swarm("[TELEMETRY] Sentinel focus flows:")
            for key, stats in flows:
                src, dst, proto, sport, dport = key
                score = stats["score"]
                risk = engine.risk_level(score)
                logbus.swarm(
                    f"  [{risk}] {src}:{sport} → {dst}:{dport} | pkts={stats['packets']}, bytes={stats['bytes']}, score={score}"
                )

        mutate_codex(console, logbus)

        for _ in range(TELEMETRY_INTERVAL_SEC):
            if console.stop_requested():
                break
            time.sleep(1)

    logbus.swarm("[SHUTDOWN] Telemetry loop exiting.")

def mutate_codex(console: ASIConsole, logbus: LogBus):
    logbus.swarm("[MUTATION] Symbolic logic tree checkpointed.")
    # Hook for future adaptive logic: config reloads, rule updates, ML model refresh, etc.

# =========================
# PERSONA + BIOMETRICS (Scaffolds)
# =========================
def persona_overlay(console: ASIConsole, logbus: LogBus):
    persona = os.getenv("USER_PERSONA", "observer")
    logbus.swarm(f"[PERSONA] Active persona: {persona}")
    # Future: persona-driven alert thresholds, language, timezone mimicry

def biometric_resonance(console: ASIConsole, logbus: LogBus):
    logbus.swarm("[BIOMETRICS] Resonance mapping scaffold online.")
    # Future: integrate OpenCV/TensorFlow for local biometric telemetry

# =========================
# THREAD STARTER
# =========================
def start_gui():
    app = QApplication(sys.argv)
    console = ASIConsole()
    logbus = LogBus(console)
    flow_table = FlowTable()
    engine = ThreatEngine(flow_table)

    threads = []

    t_sniffer = threading.Thread(
        target=divert_sniffer,
        args=(console, logbus, flow_table, engine),
        daemon=True
    )
    threads.append(t_sniffer)

    t_telemetry = threading.Thread(
        target=telemetry_loop,
        args=(console, logbus, flow_table, engine),
        daemon=True
    )
    threads.append(t_telemetry)

    t_persona = threading.Thread(
        target=persona_overlay,
        args=(console, logbus),
        daemon=True
    )
    threads.append(t_persona)

    t_bio = threading.Thread(
        target=biometric_resonance,
        args=(console, logbus),
        daemon=True
    )
    threads.append(t_bio)

    for t in threads:
        t.start()

    console.show()
    exit_code = app.exec_()
    return exit_code

if __name__ == "__main__":
    sys.exit(start_gui())
