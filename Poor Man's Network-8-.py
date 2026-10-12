#!/usr/bin/env python3
# Poor Man's Network v4.3 - Autonomous Ad-Blocking Cluster OS Node
# Author: killer666 + Copilot

import importlib
import importlib.util
import subprocess
import sys
import os
import socket
import threading
import json
import time
import queue
import base64
import hashlib
import random

# -----------------------------
# AUTOLOADER
# -----------------------------
REQUIRED_LIBS = [
    "tkinter",
    "psutil",
    "GPUtil",
    "cryptography",
    "requests",
]

def autoload():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[AUTOLOADER] Missing {lib}, attempting install...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception as e:
                print(f"[AUTOLOADER] Failed to install {lib}: {e}")

autoload()

import tkinter as tk
from tkinter import ttk
import psutil
import GPUtil
import requests
from cryptography.fernet import Fernet

# -----------------------------
# CONFIG
# -----------------------------
CLUSTER_ID = "PMN-CLUSTER-001"
NODE_PORT = 50900          # TCP encrypted messaging/storage/plugins/tasks
BROADCAST_PORT = 50901     # UDP presence/ad-intel
BROADCAST_INTERVAL = 3

PLUGIN_DIR = os.path.join(os.path.dirname(__file__), "plugins")
NODE_ROLES = ["GAMING", "STORAGE", "UTILITY", "MONITOR"]

SHARED_PASSPHRASE = "poor-man-network-secret"

AD_RULE_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
]

CPU_CAP = 70.0  # cluster CPU cap; GUI is now throttled to be lighter

def make_fernet_key(passphrase: str) -> bytes:
    h = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(h)

FERNET = Fernet(make_fernet_key(SHARED_PASSPHRASE))

# -----------------------------
# GLOBAL STATE
# -----------------------------
node_name = socket.gethostname()
node_role = "UTILITY"
node_id = f"{node_name}-{int(time.time())}"

known_nodes = {}        # host -> {ip, last_seen, role, node_id}
telemetry_data = {}     # host -> {cpu, ram, vram, temp, gpu, ts}
ad_intel = []           # list of {host, ad, ts}
ad_rules = set()        # cluster-wide ad rules (domains/patterns)
storage_index_local = {}  # local storage index
plugins = {}            # name -> module
logs = queue.Queue()

task_queue_local = queue.Queue()
tasks_cluster = {}      # task_id -> task_info

task_counter = 0
task_lock = threading.Lock()

# -----------------------------
# LOGGING
# -----------------------------
def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    logs.put(line)

# -----------------------------
# NETWORK HELPERS
# -----------------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

LOCAL_IP = get_local_ip()

# -----------------------------
# ROLE AUTO-DETECTION
# -----------------------------
def auto_detect_role():
    try:
        gpus = GPUtil.getGPUs()
        if gpus:
            return "GAMING"
    except Exception:
        pass
    try:
        disk = psutil.disk_usage(os.path.expanduser("~"))
        if disk.total > 200 * 1024**3:
            return "STORAGE"
    except Exception:
        pass
    return random.choice(["UTILITY", "MONITOR"])

node_role = auto_detect_role()

# -----------------------------
# PLUGIN SYSTEM
# -----------------------------
def load_plugins():
    global plugins
    plugins.clear()
    if not os.path.isdir(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, exist_ok=True)
        return
    for fname in os.listdir(PLUGIN_DIR):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(PLUGIN_DIR, fname)
        mod_name = f"plugin_{fname[:-3]}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec and spec.loader:
            try:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                plugins[fname[:-3]] = mod
                log(f"[PLUGIN] Loaded {fname}")
            except Exception as e:
                log(f"[PLUGIN] Failed to load {fname}: {e}")

def execute_plugin(plugin_name, payload):
    mod = plugins.get(plugin_name)
    if not mod:
        log(f"[PLUGIN] Not found: {plugin_name}")
        return {"status": "error", "reason": "plugin_not_found"}
    try:
        if hasattr(mod, "run"):
            return mod.run({
                "node_name": node_name,
                "node_id": node_id,
                "role": node_role,
                "payload": payload
            })
        else:
            log(f"[PLUGIN] {plugin_name} has no run()")
            return {"status": "error", "reason": "no_run"}
    except Exception as e:
        log(f"[PLUGIN] Error in {plugin_name}: {e}")
        return {"status": "error", "reason": str(e)}

# -----------------------------
# TELEMETRY
# -----------------------------
def collect_gpu_telemetry():
    try:
        gpus = GPUtil.getGPUs()
        if not gpus:
            return None
        gpu = gpus[0]
        return {
            "name": gpu.name,
            "load": gpu.load * 100.0,
            "mem_used": gpu.memoryUsed,
            "mem_total": gpu.memoryTotal,
            "temp": gpu.temperature
        }
    except Exception:
        return None

def collect_telemetry():
    cpu = psutil.cpu_percent(interval=0.2)
    ram = psutil.virtual_memory().percent
    temp = None
    try:
        sensors = psutil.sensors_temperatures()
        if sensors:
            for name, entries in sensors.items():
                if entries:
                    temp = entries[0].current
                    break
    except Exception:
        temp = None
    vram = None
    gpu = collect_gpu_telemetry()
    t = {
        "cpu": cpu,
        "ram": ram,
        "vram": vram,
        "temp": temp,
        "gpu": gpu,
        "ts": time.time()
    }
    telemetry_data[node_name] = t
    return t

def get_node_cpu(host):
    data = telemetry_data.get(host)
    if not data:
        return None
    return data.get("cpu")

def node_health_score(host, info):
    cpu = get_node_cpu(host)
    ram = telemetry_data.get(host, {}).get("ram")
    now = time.time()
    age = now - info.get("last_seen", now)
    if cpu is None:
        cpu = 100.0
    if ram is None:
        ram = 100.0
    score = cpu * 0.6 + ram * 0.3 + age * 0.1
    return score

# -----------------------------
# STORAGE INDEXING
# -----------------------------
def build_storage_index(max_files=3000):
    home = os.path.expanduser("~")
    index = []
    for root, dirs, files in os.walk(home):
        for f in files:
            full = os.path.join(root, f)
            try:
                size = os.path.getsize(full)
            except Exception:
                size = None
            index.append({
                "path": full,
                "size": size
            })
        if len(index) > max_files:
            break
    return index

def refresh_storage_index():
    global storage_index_local
    storage_index_local = {
        "node": node_name,
        "ts": time.time(),
        "files": build_storage_index()
    }
    log(f"[STORAGE] Indexed {len(storage_index_local['files'])} files locally")

# -----------------------------
# AD RULES
# -----------------------------
def fetch_ad_rules_from_internet():
    global ad_rules
    new_rules = set()
    for url in AD_RULE_URLS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("!"):
                        continue
                    new_rules.add(line)
                log(f"[AD] Fetched rules from {url} ({len(new_rules)} total)")
        except Exception as e:
            log(f"[AD] Failed to fetch {url}: {e}")
    if new_rules:
        ad_rules |= new_rules
        log(f"[AD] Total rules in memory: {len(ad_rules)}")

def ad_rules_sync_loop():
    while True:
        if node_role in ("UTILITY", "STORAGE", "MONITOR"):
            fetch_ad_rules_from_internet()
        share_ad_rules_with_cluster()
        time.sleep(300)

def share_ad_rules_with_cluster():
    sample = list(ad_rules)[:500]
    payload = {
        "type": "ad_rules_sync",
        "rules": sample,
        "node": node_name,
        "ts": time.time()
    }
    for host, info in list(known_nodes.items()):
        ip = info["ip"]
        send_request(ip, payload)

def merge_ad_rules_from_node(rules):
    global ad_rules
    before = len(ad_rules)
    ad_rules |= set(rules)
    after = len(ad_rules)
    if after > before:
        log(f"[AD] Merged {after - before} new rules from cluster")

# -----------------------------
# TASK SCHEDULER
# -----------------------------
def create_task(payload, preferred_role=None, plugin=None, auto=True):
    global task_counter
    with task_lock:
        task_counter += 1
        task_id = f"task-{node_name}-{task_counter}"
    task_info = {
        "id": task_id,
        "creator": node_name,
        "preferred_role": preferred_role,
        "plugin": plugin,
        "payload": payload,
        "status": "pending",
        "result": None,
        "ts": time.time(),
        "auto": auto,
    }
    tasks_cluster[task_id] = task_info
    log(f"[TASK] Created {task_id} (role={preferred_role}, plugin={plugin})")
    dispatch_task(task_info)
    return task_id

def choose_best_node(preferred_role=None):
    candidates = []

    local_info = {
        "ip": LOCAL_IP,
        "last_seen": time.time(),
        "role": node_role,
        "node_id": node_id
    }
    known_all = {node_name: local_info}
    known_all.update(known_nodes)

    for host, info in known_all.items():
        if preferred_role and info.get("role") != preferred_role:
            continue
        cpu = get_node_cpu(host)
        if cpu is None:
            cpu = 100.0
        if cpu > CPU_CAP:
            continue
        score = node_health_score(host, info)
        candidates.append((score, host, info))

    if not candidates:
        return None, None

    candidates.sort(key=lambda x: x[0])
    _, host, info = candidates[0]
    return host, info

def dispatch_task(task_info):
    preferred_role = task_info.get("preferred_role")
    host, info = choose_best_node(preferred_role=preferred_role)

    if host is None:
        log(f"[TASK] No node under CPU cap {CPU_CAP}% for {task_info['id']}, keeping pending")
        return

    ip = info["ip"]
    if host == node_name:
        log(f"[TASK] Dispatching {task_info['id']} locally (CPU-aware)")
        task_queue_local.put(task_info)
        tasks_cluster[task_info["id"]]["status"] = "running"
    else:
        log(f"[TASK] Dispatching {task_info['id']} to {host} ({ip})")
        payload = {
            "type": "task_exec_request",
            "task": task_info
        }
        resp = send_request(ip, payload)
        if resp and resp.get("type") == "task_exec_response":
            if resp.get("accepted"):
                log(f"[TASK] Node {host} accepted {task_info['id']}")
                tasks_cluster[task_info["id"]]["status"] = "running"
            else:
                log(f"[TASK] Node {host} rejected {task_info['id']}")
        else:
            log(f"[TASK] No valid response from {host} for {task_info['id']}")

def execute_task_local(task_info):
    plugin = task_info.get("plugin")
    payload = task_info.get("payload")
    if plugin:
        result = execute_plugin(plugin, payload)
    else:
        result = {
            "status": "ok",
            "node": node_name,
            "payload": payload,
            "telemetry": collect_telemetry()
        }
    task_info["status"] = "done"
    task_info["result"] = result
    tasks_cluster[task_info["id"]] = task_info
    log(f"[TASK] Executed locally {task_info['id']}")

def task_execution_loop():
    while True:
        task_info = task_queue_local.get()
        if not task_info:
            continue
        t = collect_telemetry()
        if t["cpu"] > CPU_CAP:
            log(f"[TASK] Local CPU {t['cpu']:.1f}% > cap {CPU_CAP}%, delaying {task_info['id']}")
            time.sleep(1.0)
            task_queue_local.put(task_info)
            continue
        execute_task_local(task_info)

# -----------------------------
# UDP BROADCAST
# -----------------------------
def broadcast_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        msg = {
            "type": "presence",
            "cluster_id": CLUSTER_ID,
            "hostname": node_name,
            "node_id": node_id,
            "ip": LOCAL_IP,
            "role": node_role,
            "ts": time.time()
        }
        data = json.dumps(msg).encode("utf-8")
        try:
            sock.sendto(data, ("<broadcast>", BROADCAST_PORT))
        except Exception as e:
            log(f"[NET] Broadcast error: {e}")
        time.sleep(BROADCAST_INTERVAL)

def broadcast_ad_intel(ad_text):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg = {
        "type": "ad_intel",
        "cluster_id": CLUSTER_ID,
        "hostname": node_name,
        "node_id": node_id,
        "ip": LOCAL_IP,
        "ad": ad_text,
        "ts": time.time()
    }
    data = json.dumps(msg).encode("utf-8")
    try:
        sock.sendto(data, ("<broadcast>", BROADCAST_PORT))
    except Exception as e:
        log(f"[NET] Ad broadcast error: {e}")

def listen_for_broadcasts():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", BROADCAST_PORT))
    while True:
        data, addr = sock.recvfrom(8192)
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        if msg.get("cluster_id") != CLUSTER_ID:
            continue
        mtype = msg.get("type")
        if mtype == "presence":
            host = msg["hostname"]
            known_nodes[host] = {
                "ip": msg["ip"],
                "last_seen": msg["ts"],
                "role": msg.get("role"),
                "node_id": msg.get("node_id")
            }
        elif mtype == "ad_intel":
            ad_intel.append(msg)
            if len(ad_intel) > 300:
                ad_intel.pop(0)

# -----------------------------
# TCP SERVER
# -----------------------------
def recv_json_encrypted(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        try:
            decrypted = FERNET.decrypt(buf)
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            continue
    return None

def send_json_encrypted(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    encrypted = FERNET.encrypt(data)
    conn.sendall(encrypted)

def handle_client(conn, addr):
    msg = recv_json_encrypted(conn)
    if not msg:
        conn.close()
        return
    msg_type = msg.get("type")

    if msg_type == "telemetry_request":
        t = collect_telemetry()
        send_json_encrypted(conn, {"type": "telemetry_response", "node": node_name, "data": t})

    elif msg_type == "storage_index_request":
        send_json_encrypted(conn, {"type": "storage_index_response", "node": node_name, "index": storage_index_local})

    elif msg_type == "storage_get_request":
        path = msg.get("path")
        try:
            with open(path, "rb") as f:
                content = f.read()
            send_json_encrypted(conn, {
                "type": "storage_get_response",
                "status": "ok",
                "path": path,
                "data": content.decode("latin1")
            })
        except Exception as e:
            send_json_encrypted(conn, {
                "type": "storage_get_response",
                "status": "error",
                "reason": str(e)
            })

    elif msg_type == "plugin_list_request":
        send_json_encrypted(conn, {"type": "plugin_list_response", "plugins": list(plugins.keys())})

    elif msg_type == "plugin_exec_request":
        pname = msg.get("plugin")
        payload = msg.get("payload")
        result = execute_plugin(pname, payload)
        send_json_encrypted(conn, {"type": "plugin_exec_response", "plugin": pname, "result": result})

    elif msg_type == "task_exec_request":
        task_info = msg.get("task")
        t = collect_telemetry()
        if t["cpu"] > CPU_CAP:
            log(f"[TASK] Rejecting remote task {task_info.get('id')} due to CPU {t['cpu']:.1f}% > {CPU_CAP}%")
            send_json_encrypted(conn, {"type": "task_exec_response", "accepted": False})
        else:
            preferred_role = task_info.get("preferred_role")
            if preferred_role and preferred_role != node_role:
                send_json_encrypted(conn, {"type": "task_exec_response", "accepted": False})
            else:
                task_queue_local.put(task_info)
                send_json_encrypted(conn, {"type": "task_exec_response", "accepted": True})

    elif msg_type == "ad_rules_sync":
        rules = msg.get("rules", [])
        merge_ad_rules_from_node(rules)
        send_json_encrypted(conn, {"type": "ad_rules_sync_ack", "node": node_name})

    conn.close()

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", NODE_PORT))
    srv.listen(5)
    log(f"[TCP] Listening (encrypted) on {LOCAL_IP}:{NODE_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# -----------------------------
# TCP CLIENT HELPERS
# -----------------------------
def send_request(ip, payload, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, NODE_PORT))
        send_json_encrypted(s, payload)
        resp = recv_json_encrypted(s)
        s.close()
        return resp
    except Exception as e:
        log(f"[TCP] Request error to {ip}: {e}")
        return None

# -----------------------------
# CLUSTER TELEMETRY SYNC
# -----------------------------
def telemetry_sync_loop():
    while True:
        collect_telemetry()
        for host, info in list(known_nodes.items()):
            ip = info["ip"]
            resp = send_request(ip, {"type": "telemetry_request"})
            if resp and resp.get("type") == "telemetry_response":
                telemetry_data[host] = resp["data"]
        time.sleep(5)

# -----------------------------
# GUI
# -----------------------------
def gui_main():
    global node_role

    root = tk.Tk()
    root.title(f"Poor Man's Network v4.3 - {node_name} ({node_role})")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    frame_nodes = ttk.Frame(notebook)
    notebook.add(frame_nodes, text="Nodes")
    node_list = tk.Listbox(frame_nodes)
    node_list.pack(fill="both", expand=True)

    frame_tel = ttk.Frame(notebook)
    notebook.add(frame_tel, text="Telemetry")
    tel_tree = ttk.Treeview(frame_tel, columns=("host", "cpu", "ram", "gpu", "temp"), show="headings")
    for col in ("host", "cpu", "ram", "gpu", "temp"):
        tel_tree.heading(col, text=col.upper())
    tel_tree.pack(fill="both", expand=True)

    frame_storage = ttk.Frame(notebook)
    notebook.add(frame_storage, text="Storage")
    storage_tree = ttk.Treeview(frame_storage, columns=("node", "path", "size"), show="headings")
    for col in ("node", "path", "size"):
        storage_tree.heading(col, text=col.upper())
    storage_tree.pack(fill="both", expand=True)

    btn_refresh_storage = tk.Button(frame_storage, text="Refresh Local + Cluster Storage (manual, slower GUI load)",)
    btn_refresh_storage.pack(pady=5)

    frame_ad = ttk.Frame(notebook)
    notebook.add(frame_ad, text="Ad Intel")
    ad_listbox = tk.Listbox(frame_ad)
    ad_listbox.pack(fill="both", expand=True)
    ad_entry = tk.Entry(frame_ad)
    ad_entry.pack(fill="x", padx=5, pady=5)

    def send_ad_gui():
        text = ad_entry.get().strip()
        if text:
            broadcast_ad_intel(text)
            ad_entry.delete(0, tk.END)

    ad_btn = tk.Button(frame_ad, text="Share Ad Intel", command=send_ad_gui)
    ad_btn.pack(pady=5)

    frame_rules = ttk.Frame(notebook)
    notebook.add(frame_rules, text="Ad Rules")
    rules_listbox = tk.Listbox(frame_rules)
    rules_listbox.pack(fill="both", expand=True)

    frame_plugins = ttk.Frame(notebook)
    notebook.add(frame_plugins, text="Plugins")
    plugin_listbox = tk.Listbox(frame_plugins)
    plugin_listbox.pack(fill="both", expand=True)

    btn_reload_plugins = tk.Button(frame_plugins, text="Reload Plugins", command=lambda: [load_plugins(), update_plugins()])
    btn_reload_plugins.pack(pady=5)

    plugin_payload_entry = tk.Entry(frame_plugins)
    plugin_payload_entry.insert(0, '{"example": "payload"}')
    plugin_payload_entry.pack(fill="x", padx=5, pady=5)

    plugin_target_entry = tk.Entry(frame_plugins)
    plugin_target_entry.insert(0, "localhost")
    plugin_target_entry.pack(fill="x", padx=5, pady=5)

    def exec_plugin_gui():
        pname = plugin_listbox.get(tk.ACTIVE)
        if not pname:
            return
        payload_text = plugin_payload_entry.get().strip()
        try:
            payload = json.loads(payload_text) if payload_text else {}
        except Exception:
            payload = {"raw": payload_text}
        target = plugin_target_entry.get().strip()
        if target in ("localhost", "", node_name):
            ip = LOCAL_IP
        else:
            ip = known_nodes.get(target, {}).get("ip")
        if not ip:
            log(f"[GUI] Unknown target: {target}")
            return
        resp = send_request(ip, {"type": "plugin_exec_request", "plugin": pname, "payload": payload})
        log(f"[GUI] Plugin exec response: {resp}")

    btn_exec_plugin = tk.Button(frame_plugins, text="Execute Plugin", command=exec_plugin_gui)
    btn_exec_plugin.pack(pady=5)

    frame_tasks = ttk.Frame(notebook)
    notebook.add(frame_tasks, text="Tasks")
    task_listbox = tk.Listbox(frame_tasks)
    task_listbox.pack(fill="both", expand=True)

    frame_logs = ttk.Frame(notebook)
    notebook.add(frame_logs, text="Logs")
    log_listbox = tk.Listbox(frame_logs)
    log_listbox.pack(fill="both", expand=True)

    frame_role = ttk.Frame(root)
    frame_role.pack(fill="x")
    tk.Label(frame_role, text="Node Role:").pack(side="left", padx=5)
    role_var = tk.StringVar(value=node_role)
    role_menu = ttk.Combobox(frame_role, textvariable=role_var, values=NODE_ROLES, state="readonly")
    role_menu.pack(side="left", padx=5)

    def change_role(*args):
        global node_role
        node_role = role_var.get()
        root.title(f"Poor Man's Network v4.3 - {node_name} ({node_role})")
        log(f"[ROLE] Changed role to {node_role}")

    role_var.trace_add("write", lambda *args: change_role())

    def update_nodes():
        node_list.delete(0, tk.END)
        now = time.time()
        for host, info in known_nodes.items():
            age = now - info["last_seen"]
            cpu = get_node_cpu(host)
            cpu_str = f"{cpu:.1f}%" if cpu is not None else "N/A"
            node_list.insert(
                tk.END,
                f"{host} ({info['ip']}) [{info.get('role')}] age={age:.1f}s cpu={cpu_str}"
            )
        local_cpu = get_node_cpu(node_name)
        if local_cpu is not None:
            node_list.insert(
                tk.END,
                f"{node_name} ({LOCAL_IP}) [{node_role}] age=0.0s cpu={local_cpu:.1f}% (local)"
            )

    def update_telemetry():
        for item in tel_tree.get_children():
            tel_tree.delete(item)
        for host, data in telemetry_data.items():
            gpu = data.get("gpu")
            gpu_str = "N/A"
            if gpu:
                gpu_str = f"{gpu.get('name')} {gpu.get('load', 0):.1f}% {gpu.get('temp', 0)}C"
            tel_tree.insert("", "end", values=(
                host,
                f"{data.get('cpu', '?')}%",
                f"{data.get('ram', '?')}%",
                gpu_str,
                f"{data.get('temp', 'N/A')}"
            ))

    def update_storage_manual():
        for item in storage_tree.get_children():
            storage_tree.delete(item)
        for f in storage_index_local.get("files", [])[:200]:
            storage_tree.insert("", "end", values=(node_name, f["path"], f["size"]))
        for host, info in known_nodes.items():
            ip = info["ip"]
            resp = send_request(ip, {"type": "storage_index_request"})
            if resp and resp.get("type") == "storage_index_response":
                for f in resp.get("index", {}).get("files", [])[:80]:
                    storage_tree.insert("", "end", values=(host, f["path"], f["size"]))
        log("[GUI] Manual storage refresh completed")

    btn_refresh_storage.configure(command=lambda: threading.Thread(target=update_storage_manual, daemon=True).start())

    def update_ad_intel():
        ad_listbox.delete(0, tk.END)
        for intel in ad_intel[-150:]:
            ad_listbox.insert(tk.END, f"{intel['hostname']}: {intel['ad']}")

    def update_plugins():
        plugin_listbox.delete(0, tk.END)
        for name in plugins.keys():
            plugin_listbox.insert(tk.END, name)

    def update_tasks():
        task_listbox.delete(0, tk.END)
        for tid, info in tasks_cluster.items():
            task_listbox.insert(
                tk.END,
                f"{tid} [{info['status']}] role={info.get('preferred_role')} plugin={info.get('plugin')}"
            )

    def update_logs():
        while not logs.empty():
            line = logs.get()
            log_listbox.insert(tk.END, line)
            log_listbox.yview_moveto(1.0)

    def update_rules():
        rules_listbox.delete(0, tk.END)
        for r in list(ad_rules)[:300]:
            rules_listbox.insert(tk.END, r)

    def periodic_update():
        update_nodes()
        update_telemetry()
        update_ad_intel()
        update_plugins()
        update_tasks()
        update_logs()
        update_rules()
        root.after(4000, periodic_update)  # slower GUI update for small machines

    load_plugins()
    refresh_storage_index()
    periodic_update()
    root.mainloop()

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    log(f"[NODE] Starting Poor Man's Network v4.3")
    log(f"[NODE] Name={node_name} ID={node_id} IP={LOCAL_IP} Role={node_role} Cluster={CLUSTER_ID} CPU_CAP={CPU_CAP}%")

    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_for_broadcasts, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=telemetry_sync_loop, daemon=True).start()
    threading.Thread(target=task_execution_loop, daemon=True).start()
    threading.Thread(target=ad_rules_sync_loop, daemon=True).start()

    gui_main()
