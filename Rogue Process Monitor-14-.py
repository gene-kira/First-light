import sys
import subprocess
import time
import datetime
import threading
import json
import os

# ============================================================
# Aggressive Autoloader (v15)
# ============================================================

REQUIRED_PACKAGES = [
    "psutil",
    "matplotlib",
    "scikit-learn",
    "tk",
]


def ensure_package(pkg_name, import_name=None):
    if import_name is None:
        import_name = pkg_name

    try:
        __import__(import_name)
        return True
    except ImportError:
        print(f"[AUTOLOADER] Missing '{pkg_name}', attempting installation via pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
            __import__(import_name)
            print(f"[AUTOLOADER] Successfully installed '{pkg_name}'.")
            return True
        except Exception as e:
            print(f"[AUTOLOADER] Failed to install '{pkg_name}': {e}")
            return False


def aggressive_autoload():
    ensure_package("psutil")
    ensure_package("matplotlib")
    ensure_package("scikit-learn", "sklearn")
    try:
        import tkinter  # noqa
    except ImportError:
        ensure_package("tk")


aggressive_autoload()

import psutil
import tkinter as tk
from tkinter import ttk, messagebox

ML_AVAILABLE = False
PLOTTING_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    PLOTTING_AVAILABLE = True
except Exception:
    PLOTTING_AVAILABLE = False

# ============================================================
# Logging + Persistence
# ============================================================

LOG_FILE = "rogue_monitor_v15_log.txt"
CONFIG_FILE = "rogue_monitor_v15_config.json"


def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


DEFAULT_CONFIG = {
    "mode": "SAFE",  # SAFE, AUTO_KILL_ROGUE, AUTO_KILL_CHROME_PDPRO, AUTO_KILL_ML
    "rogue_score_threshold": 60,
    "anomaly_threshold": 70.0,
    "ml_anomaly_threshold": 70.0,
    "chrome_pdpro_targets": [
        "chrome.exe",
        "google chrome for testing.exe",
        "pdpro7 hook.exe",
    ],
}


config_lock = threading.Lock()
config = DEFAULT_CONFIG.copy()


def load_config():
    global config
    if not os.path.exists(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with config_lock:
            config.update(data)
        log("Config loaded from disk.")
    except Exception as e:
        log(f"Failed to load config: {e}")


def save_config():
    with config_lock:
        data = dict(config)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log("Config saved to disk.")
    except Exception as e:
        log(f"Failed to save config: {e}")


def get_config():
    with config_lock:
        return dict(config)


def set_config_value(key, value):
    with config_lock:
        config[key] = value
    save_config()


# ============================================================
# Blacklist / config
# ============================================================

DEFAULT_BLACKLIST = [
    "google chrome for testing.exe",
    "chrome.exe",
    "chrome_sandbox.exe",
    "chrome_child.exe",
    "chrome_renderer.exe",
    "chrome_gpu.exe",
    "pdpro7 hook.exe",
    "audiohook.dll",
    "overlayinjector.exe",
    "virtualaudio.exe",
    "debug_audio_hook.exe",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "/tmp/",
    "/var/tmp/",
    "/home/",
]

SUSPICIOUS_PARENT_KEYWORDS = [
    "steamwebhelper.exe",
    "chrome.exe",
    "google chrome for testing.exe",
    "pdpro7 hook.exe",
]

blacklist_lock = threading.Lock()
blacklist = DEFAULT_BLACKLIST.copy()


def get_blacklist():
    with blacklist_lock:
        return list(blacklist)


def add_to_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name not in blacklist:
            blacklist.append(name)
    log(f"Added to blacklist: {name}")
    save_config()  # optional: could store blacklist too


def remove_from_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name in blacklist:
            blacklist.remove(name)
    log(f"Removed from blacklist: {name}")
    save_config()


def is_rogue_name(name: str) -> bool:
    if not name:
        return False
    lname = name.lower()
    with blacklist_lock:
        for entry in blacklist:
            if entry.lower() in lname:
                return True
    return False


def is_chrome_pdpro_target(name: str) -> bool:
    cfg = get_config()
    targets = cfg.get("chrome_pdpro_targets", [])
    lname = (name or "").lower()
    for t in targets:
        if t.lower() in lname:
            return True
    return False


# ============================================================
# Sandbox shared state
# ============================================================

sandbox_lock = threading.Lock()

sandbox_live_processes = []   # {pid, name, path, score, rogue, anomaly, ml_anomaly}
sandbox_history_events = []   # {ts, name, pid, path, reason, score}
sandbox_tree_lines = []       # text tree
sandbox_alerts = []           # {name, pid, path, reason, score}
sandbox_threat_level_raw = 0
sandbox_threat_level_smoothed = 0

sandbox_swarm_status = {
    "worker_count": 0,
    "avg_latency": 0.0,
    "total_processed": 0,
    "total_errors": 0,
    "slow_workers": 0,
    "restarted_workers": 0,
}

sandbox_ai_insights = {
    "last_update_ts": "",
    "summary": "",
    "recommendations": [],
    "focus_targets": [],
}

sandbox_threat_matrix = {
    "high_score": [],
    "medium_score": [],
    "low_score": [],
    "by_parent": {},
    "by_path_keyword": {},
}

sandbox_timeline_buckets = []  # {bucket_ts, count, avg_score, avg_threat}
sandbox_threat_bucket_history = []  # for plotting threat over time


def sandbox_set_live_processes(items):
    global sandbox_live_processes
    with sandbox_lock:
        sandbox_live_processes = items


def sandbox_get_live_processes():
    with sandbox_lock:
        return list(sandbox_live_processes)


def sandbox_append_history(event):
    global sandbox_history_events
    with sandbox_lock:
        sandbox_history_events.append(event)
        if len(sandbox_history_events) > 4000:
            sandbox_history_events.pop(0)


def sandbox_get_history():
    with sandbox_lock:
        return list(sandbox_history_events)


def sandbox_set_tree_lines(lines):
    global sandbox_tree_lines
    with sandbox_lock:
        sandbox_tree_lines = lines


def sandbox_get_tree_lines():
    with sandbox_lock:
        return list(sandbox_tree_lines)


def sandbox_add_alert(alert):
    global sandbox_alerts
    with sandbox_lock:
        sandbox_alerts.append(alert)
        if len(sandbox_alerts) > 800:
            sandbox_alerts.pop(0)


def sandbox_pop_alerts(max_count=10):
    global sandbox_alerts
    with sandbox_lock:
        alerts = sandbox_alerts[:max_count]
        sandbox_alerts = sandbox_alerts[max_count:]
        return alerts


def sandbox_set_threat_level(level):
    global sandbox_threat_level_raw, sandbox_threat_level_smoothed, sandbox_threat_bucket_history
    with sandbox_lock:
        sandbox_threat_level_raw = int(max(0, min(100, level)))
        sandbox_threat_level_smoothed = int(
            0.7 * sandbox_threat_level_smoothed + 0.3 * sandbox_threat_level_raw
        )
        sandbox_threat_bucket_history.append(
            (time.time(), sandbox_threat_level_smoothed)
        )
        if len(sandbox_threat_bucket_history) > 500:
            sandbox_threat_bucket_history.pop(0)


def sandbox_get_threat_level():
    with sandbox_lock:
        return sandbox_threat_level_smoothed


def sandbox_get_threat_bucket_history():
    with sandbox_lock:
        return list(sandbox_threat_bucket_history)


def sandbox_set_swarm_status(worker_count, avg_latency, total_processed, total_errors, slow_workers, restarted_workers):
    global sandbox_swarm_status
    with sandbox_lock:
        sandbox_swarm_status = {
            "worker_count": worker_count,
            "avg_latency": avg_latency,
            "total_processed": total_processed,
            "total_errors": total_errors,
            "slow_workers": slow_workers,
            "restarted_workers": restarted_workers,
        }


def sandbox_get_swarm_status():
    with sandbox_lock:
        return dict(sandbox_swarm_status)


def sandbox_set_ai_insights(summary, recommendations, focus_targets):
    global sandbox_ai_insights
    with sandbox_lock:
        sandbox_ai_insights = {
            "last_update_ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summary,
            "recommendations": recommendations,
            "focus_targets": focus_targets,
        }


def sandbox_get_ai_insights():
    with sandbox_lock:
        return dict(sandbox_ai_insights)


def sandbox_set_threat_matrix(matrix):
    global sandbox_threat_matrix
    with sandbox_lock:
        sandbox_threat_matrix = matrix


def sandbox_get_threat_matrix():
    with sandbox_lock:
        return dict(sandbox_threat_matrix)


def sandbox_set_timeline_buckets(buckets):
    global sandbox_timeline_buckets
    with sandbox_lock:
        sandbox_timeline_buckets = buckets


def sandbox_get_timeline_buckets():
    with sandbox_lock:
        return list(sandbox_timeline_buckets)


# ============================================================
# Behavior engine / scoring
# ============================================================

def estimate_signature_status(proc: psutil.Process):
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()

    if "\\windows\\" in exe_lower or "/windows/" in exe_lower:
        return "trusted"
    if "\\program files" in exe_lower or "/usr/bin" in exe_lower or "/usr/sbin" in exe_lower:
        return "likely trusted"
    if any(k in exe_lower for k in SUSPICIOUS_PATH_KEYWORDS):
        return "unknown"
    return "unknown"


def compute_reputation_score(proc: psutil.Process):
    score = 0
    reasons = []

    try:
        name = proc.name() or ""
        exe = proc.exe() or ""
        exe_lower = exe.lower()
    except Exception:
        name = ""
        exe = ""
        exe_lower = ""

    if is_rogue_name(name):
        score += 40
        reasons.append("Name matched blacklist")

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in exe_lower:
            score += 20
            reasons.append(f"Suspicious path keyword: {kw}")
            break

    try:
        parent = proc.parent()
        if parent:
            pname = parent.name() or ""
            plower = pname.lower()
            for kw in SUSPICIOUS_PARENT_KEYWORDS:
                if kw in plower:
                    score += 15
                    reasons.append(f"Suspicious parent: {pname}")
                    break
    except Exception:
        pass

    try:
        cpu = proc.cpu_percent(interval=0.0)
        mem = proc.memory_info().rss
        if cpu > 20.0:
            score += 10
            reasons.append(f"High CPU usage: {cpu:.1f}%")
        if mem > 200 * 1024 * 1024:
            score += 5
            reasons.append(f"High memory usage: {mem // (1024 * 1024)}MB")
    except Exception:
        pass

    sig = estimate_signature_status(proc)
    if sig == "unknown":
        score += 10
        reasons.append("Unknown signature / non-system path")
    elif sig == "trusted":
        score -= 10
        reasons.append("Trusted system binary")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score, reasons


# ============================================================
# Incremental scanning cache + anomaly scoring + ML features
# ============================================================

scan_cache_lock = threading.Lock()
scan_cache = {}  # pid -> {pid, name, path, score, rogue, last_seen, history_scores, cpu, rss}


def update_scan_cache(pid, name, path, score, rogue, cpu=0.0, rss=0):
    now = time.time()
    with scan_cache_lock:
        entry = scan_cache.get(pid, {
            "pid": pid,
            "name": name,
            "path": path,
            "score": score,
            "rogue": rogue,
            "last_seen": now,
            "history_scores": [],
            "cpu": cpu,
            "rss": rss,
        })
        entry["name"] = name
        entry["path"] = path
        entry["score"] = score
        entry["rogue"] = rogue
        entry["last_seen"] = now
        entry["cpu"] = cpu
        entry["rss"] = rss
        hs = entry.get("history_scores", [])
        hs.append(score)
        if len(hs) > 50:
            hs.pop(0)
        entry["history_scores"] = hs
        scan_cache[pid] = entry


def get_scan_cache_snapshot():
    with scan_cache_lock:
        return dict(scan_cache)


def prune_scan_cache(max_age=240.0):
    now = time.time()
    with scan_cache_lock:
        to_delete = [pid for pid, info in scan_cache.items()
                     if now - info.get("last_seen", 0) > max_age]
        for pid in to_delete:
            del scan_cache[pid]


def compute_anomaly_score(entry):
    hs = entry.get("history_scores", [])
    if not hs:
        return 0.0
    avg = sum(hs) / len(hs)
    last = hs[-1]
    deviation = abs(last - avg)
    anomaly = deviation + (last / 2.0)
    if anomaly > 100:
        anomaly = 100.0
    return anomaly


def build_ml_features(cache_snapshot):
    X = []
    pids = []
    for pid, e in cache_snapshot.items():
        hs = e.get("history_scores", [])
        if not hs:
            avg = e["score"]
            std = 0.0
        else:
            avg = sum(hs) / len(hs)
            if len(hs) > 1:
                m = avg
                var = sum((v - m) ** 2 for v in hs) / (len(hs) - 1)
                std = var ** 0.5
            else:
                std = 0.0
        cpu = float(e.get("cpu", 0.0))
        rss_mb = float(e.get("rss", 0) / (1024 * 1024))
        X.append([e["score"], avg, std, cpu, rss_mb])
        pids.append(pid)
    return pids, X


def compute_ml_anomaly_scores(cache_snapshot):
    if not ML_AVAILABLE:
        return {}
    pids, X = build_ml_features(cache_snapshot)
    if len(X) < 10:
        return {}
    try:
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        model.fit(X)
        scores = model.decision_function(X)  # higher is more normal
        min_s = min(scores)
        max_s = max(scores)
        if max_s == min_s:
            return {}
        ml_scores = {}
        for pid, s in zip(pids, scores):
            norm = (s - min_s) / (max_s - min_s)  # 0..1 normal
            anomaly = (1.0 - norm) * 100.0
            ml_scores[pid] = anomaly
        return ml_scores
    except Exception as e:
        log(f"ML anomaly error: {e}")
        return {}


# ============================================================
# Borg Tech: Queen + Workers + Self-Healing + ML
# ============================================================

class BorgWorker(threading.Thread):
    def __init__(self, queen, chunk, worker_id):
        super().__init__(daemon=True)
        self.queen = queen
        self.chunk = chunk
        self.worker_id = worker_id
        self.latency = 0.0
        self.processed = 0
        self.errors = 0

    def run(self):
        start = time.time()
        local_results = []
        for proc in self.chunk:
            r = self.score_proc(proc)
            if r is not None:
                local_results.append(r)
                self.processed += 1
        self.latency = time.time() - start
        self.queen.worker_report(self.worker_id, local_results, self.latency, self.processed, self.errors)

    def score_proc(self, proc):
        try:
            name = proc.info["name"]
            pid = proc.info["pid"]
            path = proc.info.get("exe", "") or ""
            if not name:
                return None

            try:
                p_obj = psutil.Process(pid)
                cpu = p_obj.cpu_percent(interval=0.0)
                rss = p_obj.memory_info().rss
            except Exception:
                cpu = 0.0
                rss = 0

            score, reasons = compute_reputation_score(psutil.Process(pid))
            rogue = (score >= 50 or is_rogue_name(name))

            update_scan_cache(pid, name, path, score, rogue, cpu=cpu, rss=rss)
            cache_snapshot = get_scan_cache_snapshot()
            entry = cache_snapshot.get(pid, {})
            anomaly = compute_anomaly_score(entry)
            ml_anomaly = 0.0  # queen will fill

            if rogue or anomaly >= 60.0:
                reason_text = "; ".join(reasons) if reasons else "Suspicious behavior"
                if anomaly >= 60.0:
                    reason_text += f"; anomaly_score={anomaly:.1f}"
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                event = {
                    "ts": ts,
                    "name": name,
                    "pid": pid,
                    "path": path,
                    "reason": reason_text,
                    "score": score,
                }
                return {
                    "live": {
                        "pid": pid,
                        "name": name,
                        "path": path,
                        "score": score,
                        "rogue": rogue,
                        "anomaly": anomaly,
                        "ml_anomaly": ml_anomaly,
                    },
                    "history": event,
                    "alert": {
                        "name": name,
                        "pid": pid,
                        "path": path,
                        "reason": reason_text,
                        "score": score,
                    },
                }
            else:
                return {
                    "live": {
                        "pid": pid,
                        "name": name,
                        "path": path,
                        "score": score,
                        "rogue": rogue,
                        "anomaly": anomaly,
                        "ml_anomaly": ml_anomaly,
                    },
                    "history": None,
                    "alert": None,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.errors += 1
            return None
        except Exception:
            self.errors += 1
            return None


class BorgQueen:
    def __init__(self):
        self.results_lock = threading.Lock()
        self.live_items = []
        self.history_batch = []
        self.alerts_batch = []

        self.worker_metrics_lock = threading.Lock()
        self.worker_metrics = {}

        self.total_processed = 0
        self.total_errors = 0
        self.slow_workers = 0
        self.restarted_workers = 0

        self.base_worker_count = 6
        self.max_worker_count = 16
        self.min_worker_count = 2

    def reset_cycle(self):
        with self.results_lock:
            self.live_items = []
            self.history_batch = []
            self.alerts_batch = []
        with self.worker_metrics_lock:
            self.worker_metrics = {}
            self.slow_workers = 0

    def worker_report(self, worker_id, worker_results, latency, processed, errors):
        with self.results_lock:
            for r in worker_results:
                self.live_items.append(r["live"])
                if r["history"] is not None:
                    self.history_batch.append(r["history"])
                if r["alert"] is not None:
                    self.alerts_batch.append(r["alert"])

        with self.worker_metrics_lock:
            self.worker_metrics[worker_id] = {
                "latency": latency,
                "processed": processed,
                "errors": errors,
            }
            self.total_processed += processed
            self.total_errors += errors

    def finalize_cycle(self):
        prune_scan_cache()

        cache_snapshot = get_scan_cache_snapshot()
        ml_scores = compute_ml_anomaly_scores(cache_snapshot)

        for item in self.live_items:
            pid = item["pid"]
            if pid in ml_scores:
                item["ml_anomaly"] = ml_scores[pid]

        sandbox_set_live_processes(self.live_items)
        for ev in self.history_batch:
            sandbox_append_history(ev)
        for al in self.alerts_batch:
            sandbox_add_alert(al)

        history = sandbox_get_history()
        recent = history[-200:]
        if recent:
            avg_score = sum(e["score"] for e in recent) / len(recent)
        else:
            avg_score = 0
        sandbox_set_threat_level(avg_score)

        with self.worker_metrics_lock:
            if self.worker_metrics:
                avg_latency = sum(m["latency"] for m in self.worker_metrics.values()) / len(self.worker_metrics)
                slow_workers = sum(1 for m in self.worker_metrics.values() if m["latency"] > 1.5)
            else:
                avg_latency = 0.0
                slow_workers = 0
            worker_count = len(self.worker_metrics)

        sandbox_set_swarm_status(
            worker_count=worker_count,
            avg_latency=avg_latency,
            total_processed=self.total_processed,
            total_errors=self.total_errors,
            slow_workers=slow_workers,
            restarted_workers=self.restarted_workers,
        )

        ThreatMatrixEngine.build_matrix(history)
        TimelineEngine.build_timeline(history, sandbox_get_threat_level())
        AIInsightEngine.generate_insights(history, sandbox_get_threat_level())

    def decide_worker_count(self, process_count):
        if process_count <= 50:
            return max(self.min_worker_count, 2)
        elif process_count <= 150:
            return max(self.min_worker_count, self.base_worker_count)
        elif process_count <= 300:
            return min(self.max_worker_count, self.base_worker_count + 4)
        else:
            return min(self.max_worker_count, self.base_worker_count + 8)

    def self_heal_and_distribute(self, procs):
        process_count = len(procs)
        worker_count = self.decide_worker_count(process_count)
        if worker_count > process_count:
            worker_count = max(1, process_count)

        with self.worker_metrics_lock:
            prev_slow = sum(1 for m in self.worker_metrics.values() if m["latency"] > 1.5)
        if prev_slow > 0:
            chunk_size = max(1, process_count // (worker_count + prev_slow))
        else:
            chunk_size = max(1, process_count // max(1, worker_count))

        workers = []
        for i in range(worker_count):
            chunk = procs[i * chunk_size:(i + 1) * chunk_size]
            if not chunk:
                continue
            w = BorgWorker(self, chunk, worker_id=i)
            w.start()
            workers.append(w)

        for w in workers:
            w.join()

        with self.worker_metrics_lock:
            slow_workers = sum(1 for m in self.worker_metrics.values() if m["latency"] > 1.5)
        if slow_workers > 0:
            self.restarted_workers += slow_workers
            log(f"BorgQueen: detected {slow_workers} slow workers, conceptually restarting them next cycle.")

        return workers


class ThreatMatrixEngine:
    @staticmethod
    def build_matrix(history):
        matrix = {
            "high_score": [],
            "medium_score": [],
            "low_score": [],
            "by_parent": {},
            "by_path_keyword": {},
        }

        for e in history[-300:]:
            s = e["score"]
            path = e["path"]
            reason = e["reason"]

            if s >= 70:
                matrix["high_score"].append(e)
            elif s >= 40:
                matrix["medium_score"].append(e)
            else:
                matrix["low_score"].append(e)

            parent_hint = None
            if "Suspicious parent:" in reason:
                parent_hint = reason.split("Suspicious parent:")[-1].strip()
            if parent_hint:
                matrix["by_parent"].setdefault(parent_hint, []).append(e)

            for kw in SUSPICIOUS_PATH_KEYWORDS:
                if kw in path.lower():
                    matrix["by_path_keyword"].setdefault(kw, []).append(e)

        sandbox_set_threat_matrix(matrix)


class TimelineEngine:
    @staticmethod
    def build_timeline(history, threat_level, bucket_seconds=300):
        if not history:
            sandbox_set_timeline_buckets([])
            return

        buckets = {}
        for e in history:
            try:
                ts = datetime.datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            bucket_key = int(ts.timestamp() // bucket_seconds) * bucket_seconds
            b = buckets.get(bucket_key, {"bucket_ts": bucket_key, "count": 0, "sum_score": 0})
            b["count"] += 1
            b["sum_score"] += e["score"]
            buckets[bucket_key] = b

        result = []
        for bk in sorted(buckets.keys()):
            b = buckets[bk]
            avg_score = b["sum_score"] / b["count"] if b["count"] else 0
            result.append({
                "bucket_ts": bk,
                "count": b["count"],
                "avg_score": avg_score,
                "avg_threat": threat_level,
            })

        sandbox_set_timeline_buckets(result)


class AIInsightEngine:
    @staticmethod
    def generate_insights(history, threat_level):
        if not history:
            summary = "No rogue events recorded yet. System appears calm."
            recommendations = [
                "Keep the monitor running to build a baseline.",
                "Add known bad tools or test binaries to the blacklist for faster detection.",
            ]
            focus_targets = []
            sandbox_set_ai_insights(summary, recommendations, focus_targets)
            return

        total = len(history)
        recent = history[-150:]
        recent_scores = [e["score"] for e in recent]
        avg_recent_score = sum(recent_scores) / len(recent_scores) if recent_scores else 0

        freq = {}
        for e in history:
            freq[e["name"]] = freq.get(e["name"], 0) + 1

        top_offenders = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]

        rare_high = []
        for e in recent:
            if freq.get(e["name"], 0) <= 2 and e["score"] >= 70:
                rare_high.append(e)

        now = datetime.datetime.now()
        burst_count = 0
        for e in recent:
            try:
                ts = datetime.datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S")
                if (now - ts).total_seconds() <= 300:
                    burst_count += 1
            except Exception:
                continue

        summary_lines = [
            f"Total rogue events: {total}",
            f"Recent average score: {avg_recent_score:.1f}",
            f"Current threat level (smoothed): {threat_level}",
        ]
        if burst_count > 20:
            summary_lines.append(f"Detection burst: {burst_count} events in the last 5 minutes.")
        elif burst_count > 5:
            summary_lines.append(f"Moderate activity: {burst_count} events in the last 5 minutes.")
        else:
            summary_lines.append(f"Low recent activity: {burst_count} events in the last 5 minutes.")

        summary_lines.append("")
        summary_lines.append("Top offenders:")
        for name, count in top_offenders:
            summary_lines.append(f"  {name}: {count} detections")

        summary = "\n".join(summary_lines)

        recommendations = []
        if threat_level >= 70:
            recommendations.append(
                "Threat level is high. Use the Threat Matrix tab to inspect high-score and parent-based clusters."
            )
            recommendations.append(
                "Capture deep snapshots for top offenders and review their network activity."
            )
        elif threat_level >= 40:
            recommendations.append(
                "Threat level is moderate. Monitor repeated offenders and verify they are expected tools."
            )
        else:
            recommendations.append(
                "Threat level is low. Use this time to refine your blacklist and baseline."
            )

        if rare_high:
            recommendations.append(
                "Rare processes with high scores detected. These may represent out-of-pattern tools or test binaries."
            )

        if burst_count > 20:
            recommendations.append(
                "Detection burst suggests scripted or automated activity. Check for scheduled tasks or batch tools."
            )

        focus_targets = []
        for name, count in top_offenders:
            focus_targets.append({
                "name": name,
                "count": count,
                "type": "repeated_offender",
            })
        for e in rare_high[:10]:
            focus_targets.append({
                "name": e["name"],
                "pid": e["pid"],
                "score": e["score"],
                "reason": e["reason"],
                "type": "rare_high_score",
            })

        sandbox_set_ai_insights(summary, recommendations, focus_targets)


# ============================================================
# Action Engine (Unified SAFE + KILL)
# ============================================================

class ActionEngine:
    """
    Unified action engine:
    - SAFE: no destructive actions
    - AUTO_KILL_ROGUE: kill processes above rogue thresholds
    - AUTO_KILL_CHROME_PDPRO: kill chrome/pdpro targets
    - AUTO_KILL_ML: kill processes with high ML anomaly
    """

    def __init__(self):
        self.lock = threading.Lock()

    def get_mode(self):
        cfg = get_config()
        return cfg.get("mode", "SAFE")

    def should_kill(self, item):
        cfg = get_config()
        mode = cfg.get("mode", "SAFE")
        rogue_thr = cfg.get("rogue_score_threshold", 60)
        anom_thr = cfg.get("anomaly_threshold", 70.0)
        ml_thr = cfg.get("ml_anomaly_threshold", 70.0)

        name = item.get("name", "")
        pid = item.get("pid")
        score = item.get("score", 0)
        anomaly = item.get("anomaly", 0.0)
        ml_anomaly = item.get("ml_anomaly", 0.0)
        rogue = item.get("rogue", False)

        if mode == "SAFE":
            return False

        if mode == "AUTO_KILL_CHROME_PDPRO":
            return is_chrome_pdpro_target(name)

        if mode == "AUTO_KILL_ROGUE":
            if rogue or score >= rogue_thr or anomaly >= anom_thr:
                return True
            return False

        if mode == "AUTO_KILL_ML":
            if ml_anomaly >= ml_thr:
                return True
            return False

        return False

    def apply_actions(self, live_items):
        mode = self.get_mode()
        if mode == "SAFE":
            return

        for item in live_items:
            if not self.should_kill(item):
                continue
            pid = item.get("pid")
            name = item.get("name", "")
            path = item.get("path", "")
            score = item.get("score", 0)
            reason = f"score={score} anomaly={item.get('anomaly', 0):.1f} ml={item.get('ml_anomaly', 0):.1f}"
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                log(f"[ACTION] KILLED process: {name} (PID={pid}) path={path} reason={reason} mode={mode}")
            except Exception as e:
                log(f"[ACTION] Failed to kill {name} (PID={pid}): {e}")


action_engine = ActionEngine()


# ============================================================
# Sandbox Scanner
# ============================================================

class SandboxScanner:
    def __init__(self):
        self.running = True
        self.queen = BorgQueen()
        self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.tree_thread = threading.Thread(target=self.tree_loop, daemon=True)
        self.scan_thread.start()
        self.tree_thread.start()

    def scan_loop(self):
        log("SandboxScanner v15 Borg swarm scan loop started")
        while self.running:
            try:
                self.borg_scan_cycle()
            except Exception as e:
                log(f"Sandbox scan error: {e}")
            time.sleep(3.0)

    def tree_loop(self):
        log("SandboxScanner v15 tree loop started")
        while self.running:
            try:
                self.build_tree()
            except Exception as e:
                log(f"Sandbox tree error: {e}")
            time.sleep(30.0)

    def borg_scan_cycle(self):
        procs = []
        for proc in psutil.process_iter(["name", "pid", "exe", "ppid"]):
            try:
                procs.append(proc)
            except Exception:
                continue

        self.queen.reset_cycle()
        self.queen.self_heal_and_distribute(procs)
        self.queen.finalize_cycle()

        # Unified action engine: apply destructive actions based on mode
        live_items = sandbox_get_live_processes()
        action_engine.apply_actions(live_items)

    def build_tree(self):
        procs = {}
        children_map = {}

        for proc in psutil.process_iter(["pid", "name", "ppid"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or ""
                ppid = proc.info["ppid"]
                procs[pid] = (name, ppid)
                children_map.setdefault(ppid, []).append(pid)
            except Exception:
                continue

        visited = set()
        lines = []

        def render_node(pid, indent=""):
            if pid in visited:
                lines.append(f"{indent}{pid} (cycle detected)")
                return
            visited.add(pid)

            if pid not in procs:
                return

            name, ppid = procs[pid]
            try:
                score, _ = compute_reputation_score(psutil.Process(pid))
            except Exception:
                score = 0

            rogue_flag = " [ROGUE]" if (score >= 50 or is_rogue_name(name)) else ""
            lines.append(f"{indent}{name} (PID={pid}, score={score}){rogue_flag}")

            for child_pid in children_map.get(pid, []):
                render_node(child_pid, indent + "    ")

        roots = [pid for pid, (name, ppid) in procs.items() if ppid == 0]

        for root_pid in roots:
            render_node(root_pid)

        sandbox_set_tree_lines(lines)


# ============================================================
# GUI
# ============================================================

class RogueMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Monitor v15.0 (Unified SAFE + Borg + ML + Autoloader)")
        self.root.geometry("1450x980")

        load_config()
        self._build_ui()

        self.sandbox = SandboxScanner()

        self.last_history_text = ""
        self.last_tree_text = ""
        self.last_live_snapshot = []
        self.last_swarm_text = ""
        self.last_ai_text = ""
        self.last_matrix_text = ""
        self.last_timeline_text = ""

        self.last_alert_popup_time = 0.0

        self.live_page = 0
        self.live_page_size = 50

        self._start_refresh_loops()

    def _build_ui(self):
        main = ttk.Notebook(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        self.tab_overview = ttk.Frame(main, padding=10)
        self.tab_blacklist = ttk.Frame(main, padding=10)
        self.tab_history = ttk.Frame(main, padding=10)
        self.tab_live = ttk.Frame(main, padding=10)
        self.tab_tree = ttk.Frame(main, padding=10)
        self.tab_snapshot = ttk.Frame(main, padding=10)
        self.tab_report = ttk.Frame(main, padding=10)
        self.tab_swarm = ttk.Frame(main, padding=10)
        self.tab_ai = ttk.Frame(main, padding=10)
        self.tab_matrix = ttk.Frame(main, padding=10)
        self.tab_timeline = ttk.Frame(main, padding=10)
        self.tab_plots = ttk.Frame(main, padding=10)

        main.add(self.tab_overview, text="Overview / Mode")
        main.add(self.tab_blacklist, text="Blacklist")
        main.add(self.tab_history, text="History / Timeline Text")
        main.add(self.tab_live, text="Live Processes")
        main.add(self.tab_tree, text="Process Tree")
        main.add(self.tab_snapshot, text="Snapshot")
        main.add(self.tab_report, text="Rogue Report")
        main.add(self.tab_swarm, text="Borg Swarm Status")
        main.add(self.tab_ai, text="AI Insights")
        main.add(self.tab_matrix, text="Threat Matrix")
        main.add(self.tab_timeline, text="Timeline View")
        main.add(self.tab_plots, text="Plots (Matplotlib)")

        self._build_overview_tab()
        self._build_blacklist_tab()
        self._build_history_tab()
        self._build_live_tab()
        self._build_tree_tab()
        self._build_snapshot_tab()
        self._build_report_tab()
        self._build_swarm_tab()
        self._build_ai_tab()
        self._build_matrix_tab()
        self._build_timeline_tab()
        self._build_plots_tab()

    def _build_overview_tab(self):
        frame = self.tab_overview

        title = ttk.Label(frame, text="Rogue Process Monitor v15.0 (Unified SAFE + Borg + ML + Autoloader)", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Unified engine:\n"
                "  - SAFE mode: no destructive actions\n"
                "  - AUTO_KILL_ROGUE: kill high-score / rogue processes\n"
                "  - AUTO_KILL_CHROME_PDPRO: kill Chrome/PDPro targets\n"
                "  - AUTO_KILL_ML: kill high ML anomaly processes\n\n"
                "Borg swarm tracks per-PID behavior over time.\n"
                "IsolationForest ML adds anomaly scoring.\n"
                "Matplotlib plots show threat level and activity over time."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ml_status = "enabled" if ML_AVAILABLE else "disabled (sklearn not found)"
        plot_status = "enabled" if PLOTTING_AVAILABLE else "disabled (matplotlib not found)"

        self.status_label = ttk.Label(
            frame,
            text=f"Status: starting... | ML={ml_status} | Plots={plot_status}",
            foreground="#00aa00"
        )
        self.status_label.grid(row=2, column=0, columnspan=4, sticky="w", pady=(5, 10))

        meter_label = ttk.Label(frame, text="Threat Meter (0-100):")
        meter_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.meter_canvas = tk.Canvas(frame, width=700, height=30, bg="#000000",
                                      highlightthickness=1, highlightbackground="#333333")
        self.meter_canvas.grid(row=4, column=0, columnspan=4, sticky="w", pady=(5, 10))

        mode_label = ttk.Label(frame, text="Action Mode:")
        mode_label.grid(row=5, column=0, sticky="w", pady=(5, 0))

        self.mode_var = tk.StringVar(value=get_config().get("mode", "SAFE"))
        modes = [
            ("SAFE (no kill)", "SAFE"),
            ("AUTO_KILL_ROGUE", "AUTO_KILL_ROGUE"),
            ("AUTO_KILL_CHROME_PDPRO", "AUTO_KILL_CHROME_PDPRO"),
            ("AUTO_KILL_ML", "AUTO_KILL_ML"),
        ]
        row = 6
        for text, val in modes:
            rb = ttk.Radiobutton(frame, text=text, value=val, variable=self.mode_var, command=self._change_mode)
            rb.grid(row=row, column=0, sticky="w", pady=(2, 0))
            row += 1

        alert_label = ttk.Label(frame, text="Recent Alerts:")
        alert_label.grid(row=5, column=1, sticky="w", pady=(5, 0))

        self.alert_box = tk.Text(frame, height=10, width=100, state="disabled", bg="#101010", fg="#ffcc00")
        self.alert_box.grid(row=6, column=1, rowspan=4, columnspan=3, sticky="we", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)
        frame.grid_columnconfigure(3, weight=1)

    def _change_mode(self):
        mode = self.mode_var.get()
        set_config_value("mode", mode)
        self._update_status(f"mode changed to {mode}")

    def _build_blacklist_tab(self):
        frame = self.tab_blacklist

        title = ttk.Label(frame, text="Rogue Process Blacklist", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Names containing any of these entries will be treated as rogue by the Borg sandbox.\n"
                "The monitor will log and alert when they are detected.\n"
                "In AUTO_KILL_ROGUE mode, high-score rogues may be killed automatically."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.blacklist_listbox = tk.Listbox(frame, height=18, width=60, bg="#101010", fg="#00ffcc")
        self.blacklist_listbox.grid(row=2, column=0, columnspan=2, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.blacklist_listbox.yview)
        scrollbar.grid(row=2, column=2, sticky="ns")
        self.blacklist_listbox.config(yscrollcommand=scrollbar.set)

        self._refresh_blacklist_listbox()

        add_label = ttk.Label(frame, text="Add entry:")
        add_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.add_entry = ttk.Entry(frame, width=40)
        self.add_entry.grid(row=3, column=1, sticky="w", pady=(5, 0))

        add_btn = ttk.Button(frame, text="Add to blacklist", command=self._add_blacklist_entry)
        add_btn.grid(row=3, column=2, sticky="w", padx=(5, 0))

        remove_btn = ttk.Button(frame, text="Remove selected", command=self._remove_selected_blacklist_entry)
        remove_btn.grid(row=4, column=0, sticky="w", pady=(10, 0))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=0)

    def _build_history_tab(self):
        frame = self.tab_history

        title = ttk.Label(frame, text="Detection History / Timeline Text", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Raw rogue detection history.\n"
                "Timeline tab shows bucketed counts and average scores."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.history_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.history_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_live_tab(self):
        frame = self.tab_live

        title = ttk.Label(frame, text="Live Process View (Borg + ML Anomaly + Action Mode)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows processes as summarized by the Borg Queen.\n"
                "Includes heuristic anomaly and optional ML anomaly per PID.\n"
                "Sorting prioritizes highest anomaly / score first."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        columns = ("pid", "name", "path", "score", "anomaly", "ml_anomaly", "rogue")
        self.live_tree = ttk.Treeview(frame, columns=columns, show="headings", height=25)
        self.live_tree.heading("pid", text="PID")
        self.live_tree.heading("name", text="Name")
        self.live_tree.heading("path", text="Path")
        self.live_tree.heading("score", text="Score")
        self.live_tree.heading("anomaly", text="Heuristic Anomaly")
        self.live_tree.heading("ml_anomaly", text="ML Anomaly")
        self.live_tree.heading("rogue", text="Rogue?")

        self.live_tree.column("pid", width=80, anchor="w")
        self.live_tree.column("name", width=200, anchor="w")
        self.live_tree.column("path", width=600, anchor="w")
        self.live_tree.column("score", width=80, anchor="center")
        self.live_tree.column("anomaly", width=120, anchor="center")
        self.live_tree.column("ml_anomaly", width=120, anchor="center")
        self.live_tree.column("rogue", width=80, anchor="center")

        self.live_tree.grid(row=2, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.live_tree.yview)
        scrollbar.grid(row=2, column=3, sticky="ns")
        self.live_tree.config(yscrollcommand=scrollbar.set)

        self.page_label = ttk.Label(frame, text="Page 1", anchor="w")
        self.page_label.grid(row=3, column=0, sticky="w", pady=(0, 5))

        prev_btn = ttk.Button(frame, text="Prev Page", command=self._prev_live_page)
        prev_btn.grid(row=3, column=1, sticky="e", pady=(0, 5))

        next_btn = ttk.Button(frame, text="Next Page", command=self._next_live_page)
        next_btn.grid(row=3, column=2, sticky="e", pady=(0, 5))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_columnconfigure(3, weight=0)
        frame.grid_rowconfigure(2, weight=1)

    def _build_tree_tab(self):
        frame = self.tab_tree

        title = ttk.Label(frame, text="Parent/Child Process Tree (Borg Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Tree is built inside the Borg sandbox and streamed here.\n"
                "Diff-based updates avoid heavy redraws."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.tree_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.tree_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_snapshot_tab(self):
        frame = self.tab_snapshot

        title = ttk.Label(frame, text="Process Snapshot (Deep Borg View)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Deep snapshot uses direct psutil calls for a single PID.\n"
                "Shows CPU, memory, threads, DLLs, and network connections."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        pid_label = ttk.Label(frame, text="PID:")
        pid_label.grid(row=2, column=0, sticky="w", pady=(5, 0))

        self.snapshot_pid_entry = ttk.Entry(frame, width=15)
        self.snapshot_pid_entry.grid(row=2, column=1, sticky="w", pady=(5, 0))

        snap_btn = ttk.Button(frame, text="Capture Deep Snapshot", command=self._capture_snapshot)
        snap_btn.grid(row=2, column=2, sticky="w", padx=(5, 0))

        self.snapshot_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.snapshot_box.grid(row=3, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_rowconfigure(3, weight=1)

    def _build_report_tab(self):
        frame = self.tab_report

        title = ttk.Label(frame, text="Rogue Process Report (Borg Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Generates a summary of rogue detections based on Borg sandbox history.\n"
                "Helps understand long-term patterns."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        report_btn = ttk.Button(frame, text="Generate Report", command=self._generate_report)
        report_btn.grid(row=2, column=0, sticky="w", pady=(5, 10))

        self.report_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.report_box.grid(row=3, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

    def _build_swarm_tab(self):
        frame = self.tab_swarm

        title = ttk.Label(frame, text="Borg Swarm Status (Self-Healing)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows health and activity of the Borg worker swarm.\n"
                "Includes slow worker count and conceptual restarts."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.swarm_box = tk.Text(frame, height=20, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.swarm_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_ai_tab(self):
        frame = self.tab_ai

        title = ttk.Label(frame, text="AI Insights (Heuristic + ML Context)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "AI Insight Engine analyzes rogue history and threat level.\n"
                "It suggests recommendations and highlights focus targets.\n"
                "All actions are advisory; destructive behavior depends on selected mode."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.ai_box = tk.Text(frame, height=22, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.ai_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_matrix_tab(self):
        frame = self.tab_matrix

        title = ttk.Label(frame, text="Threat Matrix (Score / Parent / Path)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Matrix groups events by score band, parent hints, and path keywords.\n"
                "Helps see clusters instead of isolated events."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.matrix_box = tk.Text(frame, height=24, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.matrix_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_timeline_tab(self):
        frame = self.tab_timeline

        title = ttk.Label(frame, text="Timeline View (Bucketed Activity)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows bucketed counts and average scores over time.\n"
                "Each bucket represents a time window (e.g., 5 minutes)."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.timeline_box = tk.Text(frame, height=24, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.timeline_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_plots_tab(self):
        frame = self.tab_plots

        title = ttk.Label(frame, text="Threat / Activity Plots (Matplotlib)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        status = "Matplotlib available" if PLOTTING_AVAILABLE else "Matplotlib NOT available"
        desc = ttk.Label(
            frame,
            text=(
                f"{status}.\n"
                "If available, you can open plots for:\n"
                "  - Threat level over time\n"
                "  - Bucketed activity (count vs avg score)\n"
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.plot_threat_btn = ttk.Button(frame, text="Plot Threat Level Over Time", command=self._plot_threat)
        self.plot_threat_btn.grid(row=2, column=0, sticky="w", pady=(5, 5))

        self.plot_activity_btn = ttk.Button(frame, text="Plot Bucketed Activity", command=self._plot_activity)
        self.plot_activity_btn.grid(row=3, column=0, sticky="w", pady=(5, 5))

        if not PLOTTING_AVAILABLE:
            self.plot_threat_btn.config(state="disabled")
            self.plot_activity_btn.config(state="disabled")

        frame.grid_columnconfigure(0, weight=1)

    # ---- Blacklist actions ----

    def _refresh_blacklist_listbox(self):
        self.blacklist_listbox.delete(0, tk.END)
        for entry in get_blacklist():
            self.blacklist_listbox.insert(tk.END, entry)

    def _add_blacklist_entry(self):
        text = self.add_entry.get().strip()
        if not text:
            return
        add_to_blacklist(text)
        self.add_entry.delete(0, tk.END)
        self._refresh_blacklist_listbox()
        self._update_status(f"Added '{text}' to blacklist")

    def _remove_selected_blacklist_entry(self):
        selection = self.blacklist_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        entry = self.blacklist_listbox.get(index)
        remove_from_blacklist(entry)
        self._refresh_blacklist_listbox()
        self._update_status(f"Removed '{entry}' from blacklist")

    # ---- Snapshot ----

    def _capture_snapshot(self):
        text_pid = self.snapshot_pid_entry.get().strip()
        if not text_pid.isdigit():
            messagebox.showerror("Invalid PID", "Please enter a numeric PID.")
            return
        pid = int(text_pid)
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            messagebox.showerror("Process not found", f"No process with PID {pid}.")
            return
        except psutil.AccessDenied:
            messagebox.showerror("Access denied", f"Access denied to PID {pid}.")
            return

        try:
            name = proc.name() or ""
            exe = proc.exe() or ""
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_info().rss
            threads = proc.num_threads()
            handles = getattr(proc, "num_handles", lambda: 0)()
            score, reasons = compute_reputation_score(proc)

            dlls = []
            try:
                for m in proc.memory_maps():
                    path = getattr(m, "path", "")
                    if path:
                        dlls.append(path)
            except Exception:
                dlls = []

            conns = []
            try:
                for c in proc.connections(kind="inet"):
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    conns.append(f"{c.status} {laddr} -> {raddr}")
            except Exception:
                conns = []

        except Exception as e:
            messagebox.showerror("Error", f"Failed to capture snapshot: {e}")
            return

        lines = [
            f"Deep Snapshot for PID {pid}",
            f"Name: {name}",
            f"Path: {exe}",
            f"CPU: {cpu:.1f}%",
            f"Memory: {mem // (1024 * 1024)} MB",
            f"Threads: {threads}",
            f"Handles: {handles}",
            f"Reputation score: {score}",
            f"Reasons: {', '.join(reasons) if reasons else 'None'}",
            "",
            "Loaded modules / DLLs (top 30):",
        ]
        for dll in dlls[:30]:
            lines.append(f"  {dll}")

        lines.append("")
        lines.append("Network connections (top 20):")
        for c in conns[:20]:
            lines.append(f"  {c}")

        self.snapshot_box.config(state="normal")
        self.snapshot_box.delete("1.0", tk.END)
        self.snapshot_box.insert(tk.END, "\n".join(lines))
        self.snapshot_box.config(state="disabled")

    # ---- Report ----

    def _generate_report(self):
        events = sandbox_get_history()

        if not events:
            text = "No rogue events recorded yet."
        else:
            total = len(events)
            avg_score = sum(e["score"] for e in events) / total
            freq = {}
            for e in events:
                freq[e["name"]] = freq.get(e["name"], 0) + 1
            top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]

            lines = [
                f"Rogue Process Report (Borg Sandbox)",
                f"Total events: {total}",
                f"Average score: {avg_score:.1f}",
                "",
                "Top offenders:",
            ]
            for name, count in top:
                lines.append(f"  {name}: {count} detections")

            lines.append("")
            lines.append("Recent events:")
            for e in events[-80:]:
                lines.append(
                    f"[{e['ts']}] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}"
                )

            text = "\n".join(lines)

        self.report_box.config(state="normal")
        self.report_box.delete("1.0", tk.END)
        self.report_box.insert(tk.END, text)
        self.report_box.config(state="disabled")

    # ---- Swarm status ----

    def _refresh_swarm_status(self):
        status = sandbox_get_swarm_status()
        worker_count = status.get("worker_count", 0)
        avg_latency = status.get("avg_latency", 0.0)
        total_processed = status.get("total_processed", 0)
        total_errors = status.get("total_errors", 0)
        slow_workers = status.get("slow_workers", 0)
        restarted_workers = status.get("restarted_workers", 0)

        lines = [
            "Borg Swarm Status:",
            f"  Active workers: {worker_count}",
            f"  Average worker latency: {avg_latency:.3f} s",
            f"  Total processes scanned: {total_processed}",
            f"  Total worker errors: {total_errors}",
            f"  Slow workers (last cycle): {slow_workers}",
            f"  Conceptual worker restarts (total): {restarted_workers}",
        ]

        text = "\n".join(lines)
        if text != self.last_swarm_text:
            self.last_swarm_text = text
            self.swarm_box.config(state="normal")
            self.swarm_box.delete("1.0", tk.END)
            self.swarm_box.insert(tk.END, text)
            self.swarm_box.config(state="disabled")

    # ---- AI Insights ----

    def _refresh_ai_insights(self):
        insights = sandbox_get_ai_insights()
        summary = insights.get("summary", "")
        recs = insights.get("recommendations", [])
        targets = insights.get("focus_targets", [])
        ts = insights.get("last_update_ts", "")

        lines = []
        lines.append(f"AI Insight Engine (last update: {ts})")
        lines.append("")
        if summary:
            lines.append("Summary:")
            lines.append(summary)
            lines.append("")
        if recs:
            lines.append("Recommendations:")
            for r in recs:
                lines.append(f"  - {r}")
            lines.append("")
        if targets:
            lines.append("Focus targets:")
            for t in targets:
                if t.get("type") == "repeated_offender":
                    lines.append(f"  [Repeated] {t['name']} ({t['count']} detections)")
                elif t.get("type") == "rare_high_score":
                    lines.append(
                        f"  [Rare High] {t['name']} (PID={t.get('pid', '?')}) score={t.get('score', 0)} reason={t.get('reason', '')}"
                    )

        text = "\n".join(lines)
        if text != self.last_ai_text:
            self.last_ai_text = text
            self.ai_box.config(state="normal")
            self.ai_box.delete("1.0", tk.END)
            self.ai_box.insert(tk.END, text)
            self.ai_box.config(state="disabled")

    # ---- Matrix ----

    def _refresh_matrix_view(self):
        matrix = sandbox_get_threat_matrix()
        high = matrix.get("high_score", [])
        medium = matrix.get("medium_score", [])
        low = matrix.get("low_score", [])
        by_parent = matrix.get("by_parent", {})
        by_path = matrix.get("by_path_keyword", {})

        lines = []
        lines.append("Threat Matrix:")
        lines.append("")
        lines.append(f"High-score events (>=70): {len(high)}")
        for e in high[:20]:
            lines.append(f"  [HIGH] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}")
        lines.append("")
        lines.append(f"Medium-score events (40-69): {len(medium)}")
        for e in medium[:20]:
            lines.append(f"  [MED] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}")
        lines.append("")
        lines.append(f"Low-score events (<40): {len(low)}")
        lines.append("")

        lines.append("By parent hint:")
        for parent, events in by_parent.items():
            lines.append(f"  Parent={parent} -> {len(events)} events")
        lines.append("")

        lines.append("By path keyword:")
        for kw, events in by_path.items():
            lines.append(f"  Path contains '{kw}' -> {len(events)} events")

        text = "\n".join(lines)
        if text != self.last_matrix_text:
            self.last_matrix_text = text
            self.matrix_box.config(state="normal")
            self.matrix_box.delete("1.0", tk.END)
            self.matrix_box.insert(tk.END, text)
            self.matrix_box.config(state="disabled")

    # ---- Timeline ----

    def _refresh_timeline_view(self):
        buckets = sandbox_get_timeline_buckets()
        lines = []
        lines.append("Timeline (bucketed activity):")
        lines.append("")
        for b in buckets[-40:]:
            ts = datetime.datetime.fromtimestamp(b["bucket_ts"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"  [{ts}] count={b['count']} avg_score={b['avg_score']:.1f} avg_threat={b['avg_threat']:.1f}")

        text = "\n".join(lines)
        if text != self.last_timeline_text:
            self.last_timeline_text = text
            self.timeline_box.config(state="normal")
            self.timeline_box.delete("1.0", tk.END)
            self.timeline_box.insert(tk.END, text)
            self.timeline_box.config(state="disabled")

    # ---- Threat meter ----

    def _refresh_threat_meter(self):
        level = sandbox_get_threat_level()
        self.meter_canvas.delete("all")
        w = self.meter_canvas.winfo_width()
        h = self.meter_canvas.winfo_height()
        bar_width = int((level / 100) * w)

        if level < 30:
            color = "#00ff00"
        elif level < 60:
            color = "#ffff00"
            # moderate
        else:
            color = "#ff0000"

        self.meter_canvas.create_rectangle(0, 0, bar_width, h, fill=color, outline="")
        self.meter_canvas.create_text(
            w // 2,
            h // 2,
            text=f"Threat Level: {level}",
            fill="#ffffff",
            font=("Consolas", 11),
        )

    # ---- Status ----

    def _update_status(self, text):
        ml_status = "enabled" if ML_AVAILABLE else "disabled"
        plot_status = "enabled" if PLOTTING_AVAILABLE else "disabled"
        mode = get_config().get("mode", "SAFE")
        self.status_label.config(
            text=f"Status: {text} | Mode={mode} | ML={ml_status} | Plots={plot_status}",
            foreground="#00aa00"
        )

    # ---- Live paging ----

    def _prev_live_page(self):
        if self.live_page > 0:
            self.live_page -= 1
            self._refresh_live_view(force=True)

    def _next_live_page(self):
        items = sandbox_get_live_processes()
        max_page = max(0, (len(items) - 1) // self.live_page_size)
        if self.live_page < max_page:
            self.live_page += 1
            self._refresh_live_view(force=True)

    def _refresh_live_view(self, force=False):
        items = sandbox_get_live_processes()
        items = sorted(
            items,
            key=lambda x: (
                max(x.get("ml_anomaly", 0), x.get("anomaly", 0)),
                x["score"]
            ),
            reverse=True
        )

        start = self.live_page * self.live_page_size
        end = start + self.live_page_size
        page_items = items[start:end]

        snapshot = [
            (
                i["pid"],
                i["name"],
                i["path"],
                i["score"],
                i.get("anomaly", 0),
                i.get("ml_anomaly", 0),
                i["rogue"]
            )
            for i in page_items
        ]
        if snapshot != self.last_live_snapshot or force:
            self.last_live_snapshot = snapshot
            self.live_tree.delete(*self.live_tree.get_children())
            for pid, name, path, score, anomaly, ml_anomaly, rogue in snapshot:
                rogue_str = "YES" if rogue else "NO"
                values = (pid, name, path, score, f"{anomaly:.1f}", f"{ml_anomaly:.1f}", rogue_str)
                iid = self.live_tree.insert("", tk.END, values=values)
                if rogue_str == "YES" or anomaly >= 60.0 or ml_anomaly >= 60.0:
                    self.live_tree.item(iid, tags=("rogue",))
            self.live_tree.tag_configure("rogue", background="#330000", foreground="#ff6666")

        max_page = max(0, (len(items) - 1) // self.live_page_size)
        self.page_label.config(text=f"Page {self.live_page + 1} / {max_page + 1}")

    # ---- GUI refresh loops ----

    def _start_refresh_loops(self):
        self._schedule_status_refresh()
        self._schedule_history_refresh()
        self._schedule_live_refresh()
        self._schedule_alert_refresh()
        self._schedule_tree_refresh()
        self._schedule_meter_refresh()
        self._schedule_swarm_refresh()
        self._schedule_ai_refresh()
        self._schedule_matrix_refresh()
        self._schedule_timeline_refresh()

    def _schedule_status_refresh(self):
        self._update_status(f"monitoring | blacklist entries={len(get_blacklist())}")
        self.root.after(5000, self._schedule_status_refresh)

    def _schedule_history_refresh(self):
        events = sandbox_get_history()
        lines = [
            f"[{e['ts']}] {e['name']} (PID={e['pid']}) path={e['path']} reason={e['reason']} score={e['score']}"
            for e in events
        ]
        text = "\n".join(lines)
        if text != self.last_history_text:
            self.last_history_text = text
            self.history_box.config(state="normal")
            self.history_box.delete("1.0", tk.END)
            self.history_box.insert(tk.END, text)
            self.history_box.config(state="disabled")
        self.root.after(15000, self._schedule_history_refresh)

    def _schedule_live_refresh(self):
        self._refresh_live_view()
        self.root.after(8000, self._schedule_live_refresh)

    def _schedule_alert_refresh(self):
        alerts = sandbox_pop_alerts(max_count=5)
        if alerts:
            self.alert_box.config(state="normal")
            for al in alerts:
                line = f"[ALERT] {al['name']} (PID={al['pid']}) path={al['path']} reason={al['reason']} score={al['score']}\n"
                self.alert_box.insert(tk.END, line)
                self.alert_box.see(tk.END)
            self.alert_box.config(state="disabled")

            now = time.time()
            for al in alerts:
                if now - self.last_alert_popup_time > 2.0:
                    self.last_alert_popup_time = now
                    self._show_alert_popup(al)
                    break
        self.root.after(1000, self._schedule_alert_refresh)

    def _show_alert_popup(self, al):
        def _popup():
            messagebox.showwarning(
                "Rogue Process Detected (Borg Sandbox)",
                f"Process: {al['name']}\nPID: {al['pid']}\nPath: {al['path']}\nReason: {al['reason']}\nScore: {al['score']}\n\n"
                "This process matches your rogue criteria.\n"
                "Destructive action depends on the selected mode."
            )
        self.root.after(0, _popup)

    def _schedule_tree_refresh(self):
        lines = sandbox_get_tree_lines()
        text = "\n".join(lines)
        if text != self.last_tree_text:
            self.last_tree_text = text
            self.tree_box.config(state="normal")
            self.tree_box.delete("1.0", tk.END)
            self.tree_box.insert(tk.END, text)
            self.tree_box.config(state="disabled")
        self.root.after(30000, self._schedule_tree_refresh)

    def _schedule_meter_refresh(self):
        self._refresh_threat_meter()
        self.root.after(2000, self._schedule_meter_refresh)

    def _schedule_swarm_refresh(self):
        self._refresh_swarm_status()
        self.root.after(5000, self._schedule_swarm_refresh)

    def _schedule_ai_refresh(self):
        self._refresh_ai_insights()
        self.root.after(7000, self._schedule_ai_refresh)

    def _schedule_matrix_refresh(self):
        self._refresh_matrix_view()
        self.root.after(12000, self._schedule_matrix_refresh)

    def _schedule_timeline_refresh(self):
        self._refresh_timeline_view()
        self.root.after(12000, self._schedule_timeline_refresh)

    # ---- Matplotlib plots ----

    def _plot_threat(self):
        if not PLOTTING_AVAILABLE:
            messagebox.showerror("Plots disabled", "Matplotlib is not available.")
            return
        data = sandbox_get_threat_bucket_history()
        if not data:
            messagebox.showinfo("No data", "No threat history yet.")
            return
        times = [datetime.datetime.fromtimestamp(t) for t, v in data]
        values = [v for t, v in data]
        plt.figure(figsize=(10, 4))
        plt.plot(times, values, marker="o", linestyle="-", color="red")
        plt.title("Threat Level Over Time (Smoothed)")
        plt.xlabel("Time")
        plt.ylabel("Threat Level (0-100)")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

    def _plot_activity(self):
        if not PLOTTING_AVAILABLE:
            messagebox.showerror("Plots disabled", "Matplotlib is not available.")
            return
        buckets = sandbox_get_timeline_buckets()
        if not buckets:
            messagebox.showinfo("No data", "No timeline buckets yet.")
            return
        times = [datetime.datetime.fromtimestamp(b["bucket_ts"]) for b in buckets]
        counts = [b["count"] for b in buckets]
        avg_scores = [b["avg_score"] for b in buckets]

        fig, ax1 = plt.subplots(figsize=(10, 4))
        ax2 = ax1.twinx()

        ax1.bar(times, counts, width=0.02, color="blue", alpha=0.6, label="Event Count")
        ax2.plot(times, avg_scores, color="orange", marker="o", label="Avg Score")

        ax1.set_xlabel("Time")
        ax1.set_ylabel("Event Count", color="blue")
        ax2.set_ylabel("Avg Score", color="orange")
        plt.title("Bucketed Activity: Count vs Avg Score")
        fig.autofmt_xdate()
        fig.tight_layout()
        plt.show()


# ============================================================
# Main
# ============================================================

def main():
    log("Rogue Process Monitor v15.0 (Unified SAFE + Borg + ML + Autoloader) starting")
    root = tk.Tk()
    gui = RogueMonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
