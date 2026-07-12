# ===========================================================
# BORG OS v26 — Adaptive Self-Evolving Organism (Scan-Once + Sync-Forever)
# Mode: 24/7, Mirrored System Data, Real Fitness & Evolution
# ===========================================================

import importlib
import subprocess
import sys
import os
import json
import hashlib
import time
import traceback
import threading
from datetime import datetime
import importlib.util
import shutil
import psutil  # requires: pip install psutil

# -----------------------------------------------------------
# Thread cleanup for IDE / multi-run environments
# -----------------------------------------------------------
if threading.active_count() > 1:
    print("[WARN] Previous run left threads alive. Forcing cleanup.")
    for t in threading.enumerate():
        if t is not threading.main_thread():
            try:
                t._stop()
            except Exception:
                pass

# -----------------------------------------------------------
# Autoloader for required libs
# -----------------------------------------------------------
REQUIRED_LIBS = [
    "json",
    "hashlib",
    "time",
    "os",
    "traceback",
    "threading",
    "datetime",
    "shutil",
    "psutil"
]

def ensure_libs():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except Exception:
            print(f"[Autoloader] Attempting to install missing lib: {lib}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception as e:
                print(f"[Autoloader] Failed to install {lib}: {e}")


# -----------------------------------------------------------
# Paths — cross‑OS, same folder as this file
# -----------------------------------------------------------
try:
    THIS_FILE = os.path.abspath(__file__)
except NameError:
    THIS_FILE = os.path.abspath(sys.argv[0])

BASE_DIR = os.path.join(os.path.dirname(THIS_FILE), "BORG_OS")
GENERATED_DIR = os.path.join(BASE_DIR, "generated_modules")
LOG_DIR = os.path.join(BASE_DIR, "logs")
MANIFEST_PATH = os.path.join(BASE_DIR, "generated_manifest.json")
PROFILE_PATH = os.path.join(BASE_DIR, "intelligence_profile_v26.json")
DISCOVERED_PATHS = os.path.join(BASE_DIR, "discovered_paths.json")
LAST_FULL_SCAN = os.path.join(BASE_DIR, "last_full_scan.json")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -----------------------------------------------------------
# Simple logger
# -----------------------------------------------------------
def log(msg):
    ts = datetime.utcnow().isoformat()
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(os.path.join(LOG_DIR, "borg_v26.log"), "a", encoding="utf-8") as fp:
            fp.write(line + "\n")
    except Exception:
        pass


# ===========================================================
# SYSTEM DRIVE SCANNER + MIRROR ENGINE (Scan-Once + Monthly Rescan)
# ===========================================================
BORG_SIGNATURES = [
    "brain_state",
    "organs",
    "swarm_nodes",
    "episodes",
    "metrics",
    "backups",
    "soul",
    "logs",
    "kernel",
    "persona"
]

FULL_SCAN_INTERVAL_SECONDS = 30 * 24 * 60 * 60  # ~30 days

def get_all_root_paths():
    roots = []

    if os.name == "nt":
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                roots.append(drive)
    else:
        roots.extend([
            "/",
            "/mnt",
            "/media",
            "/Volumes"
        ])

    uniq = []
    for r in roots:
        if r not in uniq:
            uniq.append(r)
    return uniq


def perform_full_scan():
    borg_paths = []
    roots = get_all_root_paths()
    log(f"[Scanner] FULL SCAN: Roots to scan: {roots}")

    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            low = dirpath.lower()
            if any(skip in low for skip in [
                "\\windows", "/windows",
                "/proc", "/sys", "/dev",
                "/usr", "/lib", "/opt", "/var",
                "/program files", "\\program files"
            ]):
                continue

            if any(sig in dirpath for sig in BORG_SIGNATURES):
                borg_paths.append(dirpath)

    log(f"[Scanner] FULL SCAN: Found BORG-related paths: {borg_paths}")

    try:
        with open(DISCOVERED_PATHS, "w", encoding="utf-8") as fp:
            json.dump({"paths": borg_paths}, fp, indent=4)
        with open(LAST_FULL_SCAN, "w", encoding="utf-8") as fp:
            json.dump({"timestamp": time.time()}, fp, indent=4)
    except Exception as e:
        log(f"[Scanner] Failed to write discovered paths: {e}")

    return borg_paths


def load_discovered_paths():
    if os.path.exists(DISCOVERED_PATHS):
        try:
            with open(DISCOVERED_PATHS, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            return data.get("paths", [])
        except Exception as e:
            log(f"[Scanner] Failed to load discovered paths: {e}")
    return []


def should_do_full_scan():
    if not os.path.exists(LAST_FULL_SCAN):
        return True
    try:
        with open(LAST_FULL_SCAN, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        last_ts = data.get("timestamp", 0)
        if time.time() - last_ts > FULL_SCAN_INTERVAL_SECONDS:
            return True
    except Exception as e:
        log(f"[Scanner] Failed to read last_full_scan: {e}")
        return True
    return False


def mirror_from_paths(borg_paths):
    for src_dir in borg_paths:
        if not os.path.exists(src_dir):
            continue
        try:
            rel = src_dir.replace(":", "")
            rel = rel.lstrip("\\/")

            mirror_root = os.path.join(BASE_DIR, "mirror", rel)
            os.makedirs(mirror_root, exist_ok=True)

            log(f"[Mirror] Syncing {src_dir} -> {mirror_root}")

            for dirpath, dirnames, filenames in os.walk(src_dir):
                rel_sub = os.path.relpath(dirpath, src_dir)
                target_dir = os.path.join(mirror_root, rel_sub)
                os.makedirs(target_dir, exist_ok=True)

                for f in filenames:
                    src_file = os.path.join(dirpath, f)
                    dst_file = os.path.join(target_dir, f)

                    try:
                        if os.path.exists(dst_file):
                            with open(src_file, "rb") as sfp:
                                src_hash = hashlib.sha256(sfp.read()).hexdigest()
                            with open(dst_file, "rb") as dfp:
                                dst_hash = hashlib.sha256(dfp.read()).hexdigest()
                            if src_hash == dst_hash:
                                continue
                        shutil.copy2(src_file, dst_file)
                    except Exception as e:
                        log(f"[Mirror] Failed to copy {src_file} -> {dst_file}: {e}")

        except Exception as e:
            log(f"[Mirror] Error processing {src_dir}: {e}")
            traceback.print_exc()

    log("[Mirror] Sync from discovered paths complete.")


def initial_scan_and_sync():
    if should_do_full_scan():
        log("[Scanner] Performing initial full scan...")
        paths = perform_full_scan()
    else:
        log("[Scanner] Using existing discovered paths.")
        paths = load_discovered_paths()

    mirror_from_paths(paths)


def periodic_rescan_if_due():
    if should_do_full_scan():
        log("[Scanner] Monthly rescan triggered...")
        paths = perform_full_scan()
        mirror_from_paths(paths)
    else:
        paths = load_discovered_paths()
        mirror_from_paths(paths)


# ===========================================================
# RESOURCE GOVERNOR
# ===========================================================
class ResourceGovernor:
    def __init__(self, cpu_limit=80.0, mem_limit=80.0):
        self.cpu_limit = cpu_limit
        self.mem_limit = mem_limit

    def check(self):
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            if cpu > self.cpu_limit or mem > self.mem_limit:
                log(f"[Governor] Throttling: CPU={cpu:.1f}%, MEM={mem:.1f}%")
                time.sleep(2.0)
                return False
        except Exception as e:
            log(f"[Governor] Error: {e}")
        return True


GOVERNOR = ResourceGovernor(cpu_limit=85.0, mem_limit=85.0)


# ===========================================================
# BORG ORGANISM CORE
# ===========================================================
class BORGOrganism:
    def __init__(self):
        log("[Organism] Initializing organism core...")

        self.brain = {
            "intelligence_level": 1.0,
            "experience_points": 0,
            "policies": []
        }
        self.organs = {}
        self.swarm = {}
        self.persona = {
            "evolution_stage": 1,
            "traits": {}
        }
        self.threat_matrix = {}
        self.kernel = {
            "simulation_depth": 1.0
        }

        self.generated_modules = []
        self.generated_instances = []
        self.organ_registry = {}
        self.module_fitness = {}

        self.scheduler_thread = None
        self.scheduler_running = False
        self.scheduler_interval = 10.0

        log("[Organism] Core initialized.")

    def broadcast_state(self):
        state = {
            "brain": self.brain,
            "persona": self.persona,
            "swarm": self.swarm,
            "kernel": self.kernel
        }
        for name, organ in self.organ_registry.items():
            try:
                if hasattr(organ, "on_state"):
                    organ.on_state(state)
            except Exception as e:
                log(f"[Organism] Broadcast error to {name}: {e}")

    def apply_policy(self, policy):
        if not isinstance(policy, dict):
            return
        self.brain["policies"].append(policy)
        if "persona_update" in policy:
            self.persona["traits"].update(policy["persona_update"])
        if "kernel_update" in policy:
            self.kernel.update(policy["kernel_update"])
        log(f"[Organism] Applied policy: {policy}")

    def register_generated_modules(self, module_entries):
        log("[Organism] Registering generated modules...")

        self.generated_modules = module_entries
        self.generated_instances = []

        for entry in module_entries:
            name = entry.get("name")
            file_path = entry.get("file")

            if not file_path or not os.path.exists(file_path):
                log(f"[Organism] Missing module file: {file_path}")
                continue

            try:
                spec = importlib.util.spec_from_file_location(name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                cls = getattr(module, name)
                instance = cls(self)

                self.generated_instances.append(instance)
                self.organ_registry[name] = instance
                self.module_fitness.setdefault(name, 0.0)

                log(f"[Organism] Loaded module: {name}")

            except Exception as e:
                log(f"[Organism] Failed to load module {name}: {e}")
                traceback.print_exc()

    def run_generated_modules(self):
        if not GOVERNOR.check():
            return {}

        results = {}

        for instance in list(self.generated_instances):
            name = instance.__class__.__name__
            start = time.time()
            try:
                output = instance.run()
                duration = time.time() - start
                results[name] = output
                self._update_fitness(name, output, duration)
            except Exception as e:
                results[name] = {"error": str(e)}
                self._update_fitness(name, {"error": str(e)}, 0.0)

        self._cull_weak_modules()
        self.broadcast_state()
        return results

    def _update_fitness(self, name, output, duration):
        score = self.module_fitness.get(name, 0.0)

        if isinstance(output, dict):
            if output.get("status") == "ok":
                score += 1.0
            if "policy" in output:
                score += 2.0
                self.apply_policy(output["policy"])
            if "error" in output:
                score -= 2.0

        if duration > 1.0:
            score -= (duration - 1.0)

        self.module_fitness[name] = score
        log(f"[Organism] Fitness: {name} -> {score:.2f} (duration={duration:.3f}s)")

    def _cull_weak_modules(self):
        weak = [name for name, score in self.module_fitness.items() if score < -10.0]
        if not weak:
            return

        log(f"[Organism] Culling weak modules: {weak}")

        self.generated_instances = [
            inst for inst in self.generated_instances
            if inst.__class__.__name__ not in weak
        ]

        for name in weak:
            self.organ_registry.pop(name, None)

    def _scheduler_loop(self):
        while True:
            if not self.scheduler_running:
                return

            try:
                log("[Organism] Scheduler tick...")
                self.run_generated_modules()
            except Exception as e:
                log(f"[Organism] Scheduler error: {e}")
                traceback.print_exc()

            time.sleep(self.scheduler_interval)

    def start_scheduler(self, interval_seconds=10.0):
        self.scheduler_interval = interval_seconds

        if self.scheduler_running:
            log("[Organism] Scheduler already running.")
            return

        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()

        log(f"[Organism] Scheduler started ({self.scheduler_interval}s).")

    def shutdown(self):
        log("[Organism] Shutting down...")
        self.scheduler_running = False

        if self.scheduler_thread and self.scheduler_thread.is_alive():
            try:
                self.scheduler_thread.join(timeout=1.0)
            except Exception:
                pass

        log("[Organism] Shutdown complete.")

    def boot(self):
        log("[Organism] Booting...")

        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                modules = manifest.get("modules", [])
                self.register_generated_modules(modules)
            except Exception as e:
                log(f"[Organism] Manifest load error: {e}")
                traceback.print_exc()

        log("[Organism] Boot pass running modules...")
        self.run_generated_modules()

        log("[Organism] Boot complete.")


# ===========================================================
# DATA INTELLIGENCE ENGINE (DIE)
# ===========================================================
class DataIntelligenceEngine:
    def __init__(self, organism):
        log("[DIE] Initializing...")
        self.organism = organism
        self.data_paths = []
        self.unified_dataset = {
            "brain": {},
            "organs": {},
            "swarm": {},
            "episodes": [],
            "metrics": {},
            "telemetry": {},
            "persona": {},
            "threat_matrix": {},
            "kernel": {},
            "soul": {},
            "backups": {}
        }
        self.upgrade_patch = {}
        log("[DIE] Ready.")

    def scan_all_data(self):
        log("[DIE] Scanning data in BASE_DIR + mirror...")
        signatures = BORG_SIGNATURES

        for root, dirs, files in os.walk(BASE_DIR):
            if any(sig in root for sig in signatures):
                for f in files:
                    if f.endswith((".json", ".borg", ".log")):
                        self.data_paths.append(os.path.join(root, f))

    def load_all_data(self):
        log("[DIE] Loading data...")
        for path in self.data_paths:
            try:
                if path.endswith(".json"):
                    with open(path, "r", encoding="utf-8") as fp:
                        self._merge_data(path, json.load(fp))

                elif path.endswith(".borg"):
                    with open(path, "rb") as fp:
                        raw = fp.read()
                        self.unified_dataset["backups"][path] = hashlib.sha256(raw).hexdigest()

                elif path.endswith(".log"):
                    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                        self.unified_dataset["telemetry"][path] = {
                            "size": len(content),
                            "hash": hashlib.sha256(content.encode()).hexdigest()
                        }

            except Exception as e:
                log(f"[DIE] Load error: {path} -> {e}")
                traceback.print_exc()

    def _merge_data(self, path, data):
        p = path.lower()
        if "brain_state" in p:
            self.unified_dataset["brain"].update(data)
        elif "organs" in p:
            self.unified_dataset["organs"][os.path.basename(path).replace(".json", "")] = data
        elif "swarm_nodes" in p:
            self.unified_dataset["swarm"][os.path.basename(path).replace(".json", "")] = data
        elif "episodes" in p:
            self.unified_dataset["episodes"].append(data)
        elif "metrics" in p:
            self.unified_dataset["metrics"].update(data)
        elif "soul" in p:
            self.unified_dataset["soul"].update(data)
        elif "kernel" in p:
            self.unified_dataset["kernel"].update(data)
        elif "persona" in p:
            self.unified_dataset["persona"].update(data)

    def analyze(self):
        log("[DIE] Analyzing...")
        self.upgrade_patch = {
            "brain": self._upgrade_brain(),
            "organs": self._upgrade_organs(),
            "swarm": self._upgrade_swarm(),
            "persona": self._upgrade_persona(),
            "threat_matrix": self._upgrade_threat_matrix(),
            "kernel": self._upgrade_kernel()
        }

        blueprints = self._design_new_modules()
        manifest = self._load_manifest()
        generated = self._generate_code_modules(blueprints, manifest)
        self._update_manifest(generated, manifest)

    def _upgrade_brain(self):
        b = self.unified_dataset["brain"]
        b["intelligence_level"] = b.get("intelligence_level", 1) + 0.5
        b["experience_points"] = b.get("experience_points", 0) + len(self.unified_dataset["episodes"])
        return b

    def _upgrade_organs(self):
        out = {}
        for organ, data in self.unified_dataset["organs"].items():
            data["efficiency"] = data.get("efficiency", 1.0) * 1.08
            out[organ] = data
        return out

    def _upgrade_swarm(self):
        out = {}
        for node, data in self.unified_dataset["swarm"].items():
            data["sync_strength"] = data.get("sync_strength", 1.0) * 1.12
            out[node] = data
        return out

    def _upgrade_persona(self):
        p = self.unified_dataset["persona"]
        p["evolution_stage"] = p.get("evolution_stage", 1) + 1
        return p

    def _upgrade_threat_matrix(self):
        tm = self.unified_dataset["threat_matrix"]
        tm["revision"] = tm.get("revision", 0) + 1
        return tm

    def _upgrade_kernel(self):
        k = self.unified_dataset["kernel"]
        k["simulation_depth"] = k.get("simulation_depth", 1) + 0.75
        return k

    def _design_new_modules(self):
        bp = []

        if self.unified_dataset["episodes"]:
            bp.append({
                "name": "EpisodeAnalyzer",
                "purpose": "Analyze episodes and generate policies.",
                "inputs": ["episodes", "persona"],
                "outputs": ["policy"]
            })

        if self.unified_dataset["swarm"]:
            bp.append({
                "name": "SwarmCoordinator",
                "purpose": "Coordinate swarm nodes and optimize sync.",
                "inputs": ["swarm", "kernel"],
                "outputs": ["policy"]
            })

        bp.append({
            "name": "PersonaEvolutionEngine",
            "purpose": "Evolve persona traits based on episodes.",
            "inputs": ["persona", "episodes"],
            "outputs": ["policy"]
        })

        return bp

    def _load_manifest(self):
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    return json.load(fp)
            except Exception:
                return {}
        return {}

    def _mutate_blueprint(self, bp, gen):
        m = dict(bp)
        m["name"] = f"{bp['name']}_Gen{gen}"
        m["purpose"] += f" (gen {gen})"
        return m

    def _generate_code_modules(self, blueprints, manifest):
        gen = int(manifest.get("generation", 0)) + 1
        out = []

        for bp in blueprints:
            variants = [bp, self._mutate_blueprint(bp, gen)]

            for v in variants:
                name = v["name"]
                file_path = os.path.join(GENERATED_DIR, f"{name}.py")

                code = self._build_module_code(v, gen)
                with open(file_path, "w", encoding="utf-8") as fp:
                    fp.write(code)

                out.append({
                    "name": name,
                    "file": file_path,
                    "timestamp": datetime.utcnow().isoformat(),
                    "generation": gen
                })

                log(f"[DIE] Generated: {file_path}")

        return out

    def _build_module_code(self, bp, gen):
        return f'''"""
Auto-generated module: {bp["name"]}
Purpose: {bp["purpose"]}
Generation: {gen}
"""

import time

class {bp["name"]}:
    def __init__(self, organism):
        self.organism = organism
        self.state = {{}}

    def on_state(self, state):
        self.state = state

    def run(self):
        persona = self.state.get("persona", {{}})
        kernel = self.state.get("kernel", {{}})

        policy = {{
            "persona_update": {{
                "last_module": "{bp["name"]}",
                "generation": {gen},
                "evolution_hint": "auto"
            }},
            "kernel_update": {{
                "last_activity_ts": time.time(),
                "simulation_depth": kernel.get("simulation_depth", 1.0) + 0.01
            }}
        }}
        return {{
            "status": "ok",
            "generation": {gen},
            "timestamp": time.time(),
            "policy": policy
        }}
'''

    def _update_manifest(self, generated, manifest):
        manifest.setdefault("modules", [])
        manifest["modules"].extend(generated)
        manifest["generation"] = int(manifest.get("generation", 0)) + 1

        with open(MANIFEST_PATH, "w", encoding="utf-8") as fp:
            json.dump(manifest, fp, indent=4)

        log("[DIE] Manifest updated.")

    def inject(self):
        for key, patch in self.upgrade_patch.items():
            setattr(self.organism, key, patch)

        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                self.organism.register_generated_modules(manifest.get("modules", []))
            except Exception as e:
                log(f"[DIE] Inject error: {e}")
                traceback.print_exc()

    def write_profile(self):
        try:
            with open(PROFILE_PATH, "w", encoding="utf-8") as fp:
                json.dump({
                    "timestamp": time.time(),
                    "dataset": self.unified_dataset,
                    "upgrade_patch": self.upgrade_patch
                }, fp, indent=4)
            log("[DIE] Profile written.")
        except Exception as e:
            log(f"[DIE] Profile write error: {e}")

    def run(self):
        log("[DIE] Running evolution cycle...")
        self.scan_all_data()
        self.load_all_data()
        self.analyze()
        self.inject()
        self.write_profile()
        log("[DIE] Evolution complete.")


# ===========================================================
# ENTRYPOINT — 24/7 daemon mode with Scan-Once + Monthly Rescan
# ===========================================================
if __name__ == "__main__":
    organism = None
    try:
        log("[MAIN] Starting BORG OS v26 backbone...")

        ensure_libs()

        initial_scan_and_sync()

        organism = BORGOrganism()
        organism.boot()

        die = DataIntelligenceEngine(organism)
        die.run()

        organism.start_scheduler(10)

        log("[MAIN] BORG OS v26 running in 24/7 adaptive sync mode.")

        while True:
            try:
                time.sleep(1800)  # 30 minutes

                log("[MAIN] 24/7 cycle: sync from discovered paths + run DIE evolution...")
                periodic_rescan_if_due()
                die = DataIntelligenceEngine(organism)
                die.run()

                if not organism.scheduler_running:
                    organism.start_scheduler(10)

            except Exception as e:
                log(f"[MAIN] 24/7 loop error: {e}")
                traceback.print_exc()
                time.sleep(5)

    except Exception as e:
        log("[CRITICAL ERROR] Startup crash detected!")
        log(str(e))
        traceback.print_exc()

    finally:
        if organism is not None:
            organism.shutdown()
