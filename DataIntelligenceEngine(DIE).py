# ===========================================================
# BORG OS v26 — Stable Cross‑OS Backbone with 24/7 Self‑Evolving DIE
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
# Autoloader for required libs (mostly stdlib, kept generic)
# -----------------------------------------------------------
REQUIRED_LIBS = [
    "json",
    "hashlib",
    "time",
    "os",
    "traceback",
    "threading",
    "datetime"
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
MANIFEST_PATH = os.path.join(BASE_DIR, "generated_manifest.json")
PROFILE_PATH = os.path.join(BASE_DIR, "intelligence_profile_v26.json")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)


# ===========================================================
# BORG ORGANISM CORE
# ===========================================================
class BORGOrganism:
    def __init__(self):
        print("[Organism] Initializing organism core...")

        self.brain = {}
        self.organs = {}
        self.swarm = {}
        self.persona = {}
        self.threat_matrix = {}
        self.kernel = {}

        self.generated_modules = []
        self.generated_instances = []
        self.organ_registry = {}
        self.module_fitness = {}

        self.scheduler_thread = None
        self.scheduler_running = False
        self.scheduler_interval = 10.0

        print("[Organism] Core initialized.")

    # -------------------------------------------------------
    # Register generated modules (auto‑wire as organs)
    # -------------------------------------------------------
    def register_generated_modules(self, module_entries):
        print("[Organism] Registering generated modules...")

        self.generated_modules = module_entries
        self.generated_instances = []

        for entry in module_entries:
            name = entry.get("name")
            file_path = entry.get("file")

            if not file_path or not os.path.exists(file_path):
                print(f"[Organism] Missing module file: {file_path}")
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

                print(f"[Organism] Loaded module: {name}")

            except Exception as e:
                print(f"[Organism] Failed to load module {name}: {e}")
                traceback.print_exc()

    # -------------------------------------------------------
    # Run generated modules once
    # -------------------------------------------------------
    def run_generated_modules(self):
        results = {}

        for instance in list(self.generated_instances):
            name = instance.__class__.__name__
            try:
                output = instance.run()
                results[name] = output
                self._update_fitness(name, output)
            except Exception as e:
                results[name] = {"error": str(e)}
                self._update_fitness(name, {"error": str(e)})

        self._cull_weak_modules()
        return results

    # -------------------------------------------------------
    # Fitness scoring + culling
    # -------------------------------------------------------
    def _update_fitness(self, name, output):
        score = self.module_fitness.get(name, 0.0)

        if isinstance(output, dict):
            if output.get("status") == "ok":
                score += 1.0
            if "error" in output:
                score -= 1.0

        self.module_fitness[name] = score
        print(f"[Organism] Fitness: {name} -> {score:.2f}")

    def _cull_weak_modules(self):
        weak = [name for name, score in self.module_fitness.items() if score < -5.0]
        if not weak:
            return

        print(f"[Organism] Culling weak modules: {weak}")

        self.generated_instances = [
            inst for inst in self.generated_instances
            if inst.__class__.__name__ not in weak
        ]

        for name in weak:
            self.organ_registry.pop(name, None)

    # -------------------------------------------------------
    # Scheduler — continuous execution, shutdown‑safe
    # -------------------------------------------------------
    def _scheduler_loop(self):
        while True:
            if not self.scheduler_running:
                return  # exit thread immediately

            try:
                print("[Organism] Scheduler tick...")
                self.run_generated_modules()
            except Exception as e:
                print(f"[Organism] Scheduler error: {e}")
                traceback.print_exc()

            time.sleep(self.scheduler_interval)

    def start_scheduler(self, interval_seconds=10.0):
        self.scheduler_interval = interval_seconds

        if self.scheduler_running:
            print("[Organism] Scheduler already running.")
            return

        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()

        print(f"[Organism] Scheduler started ({self.scheduler_interval}s).")

    def shutdown(self):
        print("[Organism] Shutting down...")
        self.scheduler_running = False

        if self.scheduler_thread and self.scheduler_thread.is_alive():
            try:
                self.scheduler_thread.join(timeout=1.0)
            except Exception:
                pass

        print("[Organism] Shutdown complete.")

    # -------------------------------------------------------
    # Boot sequence
    # -------------------------------------------------------
    def boot(self):
        print("[Organism] Booting...")

        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                modules = manifest.get("modules", [])
                self.register_generated_modules(modules)
            except Exception as e:
                print(f"[Organism] Manifest load error: {e}")
                traceback.print_exc()

        print("[Organism] Boot pass running modules...")
        self.run_generated_modules()

        print("[Organism] Boot complete.")


# ===========================================================
# DATA INTELLIGENCE ENGINE (DIE)
# ===========================================================
class DataIntelligenceEngine:
    def __init__(self, organism):
        print("[DIE] Initializing...")
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
        print("[DIE] Ready.")

    # -------------------------------------------------------
    # Scan data under BORG_OS
    # -------------------------------------------------------
    def scan_all_data(self):
        print("[DIE] Scanning data...")
        signatures = [
            "brain_state", "organs", "swarm_nodes",
            "episodes", "metrics", "backups", "soul",
            "logs", "kernel", "persona"
        ]

        for root, dirs, files in os.walk(BASE_DIR):
            if any(sig in root for sig in signatures):
                for f in files:
                    if f.endswith((".json", ".borg", ".log")):
                        self.data_paths.append(os.path.join(root, f))

    # -------------------------------------------------------
    # Load data
    # -------------------------------------------------------
    def load_all_data(self):
        print("[DIE] Loading data...")
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
                print(f"[DIE] Load error: {path} -> {e}")
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

    # -------------------------------------------------------
    # Analyze + design + genetic evolution
    # -------------------------------------------------------
    def analyze(self):
        print("[DIE] Analyzing...")
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
                "purpose": "Analyze episodes.",
                "inputs": ["episodes"],
                "outputs": ["policy"]
            })

        if self.unified_dataset["swarm"]:
            bp.append({
                "name": "SwarmCoordinator",
                "purpose": "Coordinate swarm nodes.",
                "inputs": ["swarm"],
                "outputs": ["plan"]
            })

        bp.append({
            "name": "PersonaEvolutionEngine",
            "purpose": "Evolve persona.",
            "inputs": ["persona", "episodes"],
            "outputs": ["persona_update"]
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

                print(f"[DIE] Generated: {file_path}")

        return out

    def _build_module_code(self, bp, gen):
        return f'''"""
Auto-generated module: {bp["name"]}
Purpose: {bp["purpose"]}
Generation: {gen}
"""

class {bp["name"]}:
    def __init__(self, organism):
        self.organism = organism

    def run(self):
        return {{
            "status": "ok",
            "generation": {gen},
            "timestamp": __import__("time").time()
        }}
'''

    def _update_manifest(self, generated, manifest):
        manifest.setdefault("modules", [])
        manifest["modules"].extend(generated)
        manifest["generation"] = int(manifest.get("generation", 0)) + 1

        with open(MANIFEST_PATH, "w", encoding="utf-8") as fp:
            json.dump(manifest, fp, indent=4)

        print("[DIE] Manifest updated.")

    # -------------------------------------------------------
    # Inject into organism
    # -------------------------------------------------------
    def inject(self):
        for key, patch in self.upgrade_patch.items():
            setattr(self.organism, key, patch)

        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                self.organism.register_generated_modules(manifest.get("modules", []))
            except Exception as e:
                print(f"[DIE] Inject error: {e}")
                traceback.print_exc()

    # -------------------------------------------------------
    # Write profile
    # -------------------------------------------------------
    def write_profile(self):
        with open(PROFILE_PATH, "w", encoding="utf-8") as fp:
            json.dump({
                "timestamp": time.time(),
                "dataset": self.unified_dataset,
                "upgrade_patch": self.upgrade_patch
            }, fp, indent=4)

        print("[DIE] Profile written.")

    # -------------------------------------------------------
    # Run evolution cycle
    # -------------------------------------------------------
    def run(self):
        print("[DIE] Running evolution cycle...")
        self.scan_all_data()
        self.load_all_data()
        self.analyze()
        self.inject()
        self.write_profile()
        print("[DIE] Evolution complete.")


# ===========================================================
# ENTRYPOINT — 24/7 daemon mode
# ===========================================================
if __name__ == "__main__":
    organism = None
    try:
        print("[MAIN] Starting BORG OS v26 backbone...")

        ensure_libs()

        organism = BORGOrganism()
        organism.boot()

        die = DataIntelligenceEngine(organism)
        die.run()

        organism.start_scheduler(10)

        print("[MAIN] BORG OS v26 running in 24/7 mode.")

        # 24/7 loop — run DIE evolution every 15 minutes
        while True:
            try:
                time.sleep(900)  # 15 minutes
                print("[MAIN] 24/7 cycle: running DIE evolution...")
                die = DataIntelligenceEngine(organism)
                die.run()

                if not organism.scheduler_running:
                    organism.start_scheduler(10)

            except Exception as e:
                print("[MAIN] 24/7 loop error:", e)
                traceback.print_exc()
                time.sleep(5)

    except Exception as e:
        print("\n[CRITICAL ERROR] Startup crash detected!")
        print(e)
        traceback.print_exc()

    finally:
        if organism is not None:
            organism.shutdown()
