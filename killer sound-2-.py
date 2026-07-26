import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import pythoncom
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
from datetime import datetime
import threading
import hashlib
import random
import json
import os

# === CONFIG ===
LOG_FILE = "audio_weapon_console_log.txt"
RULES_FILE = "audio_weapon_rules.json"
AUTO_REFRESH_INTERVAL = 3  # seconds
THREAT_SCORE_PORT_RISK = {22: 30, 3389: 40, 5900: 35}
HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP"}

# === RULES / STATE ===
BLOCKLIST = set()
ALLOWLIST = set()
AUTO_KILL_RULES = {
    "high_threat_score": 90,   # kill if score >= 90
}
AUTO_MUTE_RULES = {
    "medium_threat_score": 60,  # mute if score >= 60
}


def load_rules():
    global BLOCKLIST, ALLOWLIST, AUTO_KILL_RULES, AUTO_MUTE_RULES
    if not os.path.exists(RULES_FILE):
        return
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        BLOCKLIST = set(data.get("blocklist", []))
        ALLOWLIST = set(data.get("allowlist", []))
        AUTO_KILL_RULES = data.get("auto_kill_rules", AUTO_KILL_RULES)
        AUTO_MUTE_RULES = data.get("auto_mute_rules", AUTO_MUTE_RULES)
    except Exception:
        pass


def save_rules():
    data = {
        "blocklist": list(BLOCKLIST),
        "allowlist": list(ALLOWLIST),
        "auto_kill_rules": AUTO_KILL_RULES,
        "auto_mute_rules": AUTO_MUTE_RULES,
    }
    try:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


# === UTILITIES ===

def write_log(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    return line


def fake_country_lookup(ip):
    countries = ["US", "GB", "DE", "FR", "NL", "SE", "RU", "CN"]
    return random.choice(countries)


def compute_fake_bandwidth(pid):
    return random.randint(0, 500), random.randint(0, 500)  # up_kbps, down_kbps


def compute_hash(path):
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return "UNKNOWN"


def compute_threat_score(info):
    score = 0
    if info["volume"] > 0.7:
        score += 20
    for port in info["ports"]:
        score += THREAT_SCORE_PORT_RISK.get(port, 0)
    for c in info["countries"]:
        if c in HIGH_RISK_COUNTRIES:
            score += 30
    up, down = info["bandwidth"]
    if down > 1000:
        score += 25
    if up > 500:
        score += 15
    if info["exe_name"].lower() in BLOCKLIST:
        score += 50
    if info["exe_name"].lower() in ALLOWLIST:
        score -= 40
    return max(0, min(score, 100))


def classify_threat(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"


# === MAIN APP ===

class AudioWeaponConsole(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Audio Weapon Console v2 — Audio + Network Intelligence")
        self.geometry("1200x700")  # more compact

        self.auto_refresh_enabled = tk.BooleanVar(value=True)
        self.alerts_enabled = tk.BooleanVar(value=True)

        load_rules()
        self._build_ui()
        self._start_auto_refresh()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=4)

        ttk.Button(top, text="Manual Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(top, text="Auto Refresh", variable=self.auto_refresh_enabled).pack(side=tk.LEFT, padx=4)

        self.alert_button = tk.Button(
            top,
            text="ALERTS: ON",
            command=self.toggle_alerts,
            fg="green"
        )
        self.alert_button.pack(side=tk.LEFT, padx=8)

        ttk.Button(top, text="Edit Rules", command=self.edit_rules_popup).pack(side=tk.LEFT, padx=4)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # === TABLE TAB ===
        self.table_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.table_frame, text="Audio + Network")

        self.tree = ttk.Treeview(
            self.table_frame,
            columns=(
                "pid", "name", "volume", "muted",
                "local_ip", "local_port",
                "remote_ip", "remote_port",
                "country", "up", "down",
                "parent", "exe", "hash",
                "threat", "score"
            ),
            show="headings",
            height=16
        )

        headings = {
            "pid": "PID",
            "name": "Process",
            "volume": "Vol",
            "muted": "Muted",
            "local_ip": "Local IP",
            "local_port": "LPort",
            "remote_ip": "Remote IP",
            "remote_port": "RPort",
            "country": "Country",
            "up": "Up KB/s",
            "down": "Down KB/s",
            "parent": "Parent",
            "exe": "Exe Path",
            "hash": "SHA256 (partial)",
            "threat": "Threat",
            "score": "Score",
        }

        widths = {
            "pid": 60,
            "name": 160,
            "volume": 60,
            "muted": 60,
            "local_ip": 110,
            "local_port": 60,
            "remote_ip": 120,
            "remote_port": 60,
            "country": 70,
            "up": 70,
            "down": 70,
            "parent": 120,
            "exe": 220,
            "hash": 180,
            "threat": 80,
            "score": 60,
        }

        for col in self.tree["columns"]:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col,
                width=widths[col],
                anchor=tk.CENTER
                if col in ("pid", "volume", "muted", "local_port", "remote_port", "country", "up", "down", "score")
                else tk.W,
            )

        self.tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        table_bottom = ttk.Frame(self.table_frame)
        table_bottom.pack(fill=tk.X, padx=4, pady=4)

        ttk.Button(table_bottom, text="Kill", command=self.kill_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Mute", command=self.mute_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Unmute", command=self.unmute_selected).pack(side=tk.LEFT, padx=3)

        ttk.Button(table_bottom, text="Blocklist +", command=self.add_blocklist_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Allowlist +", command=self.add_allowlist_selected).pack(side=tk.LEFT, padx=3)

        ttk.Label(table_bottom, text="Vol:").pack(side=tk.LEFT, padx=(12, 2))
        self.volume_scale = ttk.Scale(
            table_bottom,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            command=self.set_volume_selected,
        )
        self.volume_scale.pack(side=tk.LEFT, padx=3, fill=tk.X, expand=True)

        # === LOG TAB ===
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Timeline / Log")

        self.log_box = scrolledtext.ScrolledText(self.timeline_frame, height=18, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=8, pady=4)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT, padx=4)

        self._update_alert_button_style()

    def add_log(self, message):
        line = write_log(message)
        self.log_box.insert(tk.END, line)
        self.log_box.see(tk.END)

    def toggle_alerts(self):
        self.alerts_enabled.set(not self.alerts_enabled.get())
        self._update_alert_button_style()
        state = "ON" if self.alerts_enabled.get() else "OFF"
        self.add_log(f"Alerts toggled {state}")

    def _update_alert_button_style(self):
        if self.alerts_enabled.get():
            self.alert_button.configure(text="ALERTS: ON", fg="green")
        else:
            self.alert_button.configure(text="ALERTS: OFF", fg="red")

    def _start_auto_refresh(self):
        def loop():
            while True:
                if self.auto_refresh_enabled.get():
                    self.refresh_all()
                threading.Event().wait(AUTO_REFRESH_INTERVAL)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def refresh_all(self):
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception as e:
            self.add_log(f"ERROR: Audio session fetch failed: {e}")
            self.status.set(f"Audio error: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.add_log("Refreshing audio + network + threat view...")

        for session in sessions:
            try:
                volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                vol_level = volume_obj.GetMasterVolume()
                muted = volume_obj.GetMute()

                pid = session.Process.pid if session.Process else None
                name = session.Process.name() if session.Process else "System"

                local_ip = "-"
                local_port = "-"
                remote_ip = "-"
                remote_port = "-"
                countries = set()
                ports = set()

                parent_name = "-"
                exe_path = "-"
                hash_short = "-"
                up_kbps = 0
                down_kbps = 0

                if pid is not None:
                    try:
                        proc = psutil.Process(pid)
                        exe_path = proc.exe() or "-"
                        parent = proc.parent()
                        parent_name = parent.name() if parent else "-"
                        conns = proc.connections(kind="inet")

                        for c in conns:
                            if c.laddr:
                                local_ip = c.laddr.ip
                                local_port = c.laddr.port
                            if c.raddr:
                                remote_ip = c.raddr.ip
                                remote_port = c.raddr.port
                                ports.add(c.raddr.port)
                                country = fake_country_lookup(c.raddr.ip)
                                countries.add(country)
                    except Exception:
                        pass

                    up_kbps, down_kbps = compute_fake_bandwidth(pid)
                    file_hash = compute_hash(exe_path) if exe_path not in ("-", "") else "UNKNOWN"
                    hash_short = file_hash[:16]

                info = {
                    "pid": pid,
                    "name": name,
                    "volume": vol_level,
                    "muted": muted,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "countries": list(countries),
                    "ports": list(ports),
                    "bandwidth": (up_kbps, down_kbps),
                    "parent_name": parent_name,
                    "exe_path": exe_path,
                    "exe_name": name,
                    "hash_short": hash_short,
                }

                threat_score = compute_threat_score(info)
                threat_level = classify_threat(threat_score)

                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        pid,
                        name,
                        f"{int(vol_level * 100)}%",
                        "Yes" if muted else "No",
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        ",".join(info["countries"]) if info["countries"] else "-",
                        up_kbps,
                        down_kbps,
                        parent_name,
                        exe_path,
                        hash_short,
                        threat_level,
                        threat_score,
                    ),
                )

                self.add_log(
                    f"PID={pid} Name={name} Vol={int(vol_level*100)}% "
                    f"L={local_ip}:{local_port} R={remote_ip}:{remote_port} "
                    f"Countries={info['countries']} BW={up_kbps}/{down_kbps}KB/s "
                    f"Threat={threat_level}({threat_score})"
                )

                self._apply_auto_rules(info, threat_level, threat_score, volume_obj)

                if self.alerts_enabled.get() and threat_score >= 90:
                    self._raise_alert(info, threat_level, threat_score)

            except Exception:
                continue

        self.status.set("Audio + network + threat view refreshed")

    def _apply_auto_rules(self, info, level, score, volume_obj):
        name = info["name"]
        pid = info["pid"]

        if name.lower() in ALLOWLIST:
            return

        if name.lower() in BLOCKLIST:
            if pid is not None:
                self.add_log(f"AUTO-KILL (blocklist) PID={pid} Name={name}")
                self._kill_pid(pid, name)
            return

        kill_threshold = AUTO_KILL_RULES.get("high_threat_score", 90)
        if score >= kill_threshold and pid is not None:
            self.add_log(f"AUTO-KILL (score) PID={pid} Name={name} Score={score}")
            self._kill_pid(pid, name)
            return

        mute_threshold = AUTO_MUTE_RULES.get("medium_threat_score", 60)
        if score >= mute_threshold and pid is not None:
            try:
                volume_obj.SetMute(True, None)
                self.add_log(f"AUTO-MUTE PID={pid} Name={name} Score={score}")
            except Exception:
                pass

    def _raise_alert(self, info, level, score):
        msg = (
            f"Suspicious audio/network activity detected!\n\n"
            f"Process: {info['name']}\n"
            f"PID: {info['pid']}\n"
            f"Exe: {info['exe_path']}\n"
            f"Parent: {info['parent_name']}\n"
            f"Volume: {int(info['volume'] * 100)}%\n"
            f"Countries: {info['countries']}\n"
            f"Ports: {info['ports']}\n"
            f"Bandwidth: Up {info['bandwidth'][0]} KB/s, Down {info['bandwidth'][1]} KB/s\n"
            f"Threat Level: {level}\n"
            f"Threat Score: {score}\n\n"
            f"Do you want to kill this process now?"
        )
        self.add_log(f"ALERT: {info['name']} PID={info['pid']} Threat={level}({score})")
        answer = messagebox.askyesno("Audio Weapon Console — ALERT", msg)
        if answer and info["pid"] is not None:
            self._kill_pid(info["pid"], info["name"])

    def _get_selected(self):
        selected = self.tree.selection()
        if not selected:
            return None
        item = self.tree.item(selected[0])
        vals = item["values"]
        return {
            "pid": vals[0],
            "name": vals[1],
        }

    def _kill_pid(self, pid, name):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=3)
            for p in alive:
                p.kill()
            self.add_log(f"KILLED PID={pid} Name={name}")
            self.status.set(f"Killed {name} (PID {pid})")
        except Exception as e:
            self.add_log(f"Kill FAILED PID={pid} Name={name} Error={e}")
            messagebox.showerror("Error", f"Failed to kill process: {e}")
            self.status.set(f"Kill error: {e}")

    def kill_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        answer = messagebox.askyesno(
            "Confirm Kill",
            f"Kill process {sel['name']} (PID {sel['pid']})?"
        )
        if not answer:
            return
        self._kill_pid(sel["pid"], sel["name"])
        self.refresh_all()

    def _set_mute_state(self, pid, mute):
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception:
            return
        for session in sessions:
            try:
                spid = session.Process.pid if session.Process else None
                if spid == pid:
                    volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                    volume_obj.SetMute(mute, None)
            except Exception:
                continue

    def mute_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        self._set_mute_state(sel["pid"], True)
        self.add_log(f"MUTED PID={sel['pid']} Name={sel['name']}")
        self.status.set(f"Muted {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def unmute_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        self._set_mute_state(sel["pid"], False)
        self.add_log(f"UNMUTED PID={sel['pid']} Name={sel['name']}")
        self.status.set(f"Unmuted {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def set_volume_selected(self, value):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            return
        vol = float(value) / 100.0
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception:
            return
        for session in sessions:
            try:
                spid = session.Process.pid if session.Process else None
                if spid == sel["pid"]:
                    volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                    volume_obj.SetMasterVolume(vol, None)
            except Exception:
                continue
        self.add_log(f"SET VOLUME PID={sel['pid']} Name={sel['name']} Vol={int(float(value))}%")
        self.status.set(f"Volume set for {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def add_blocklist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        BLOCKLIST.add(sel["name"].lower())
        save_rules()
        self.add_log(f"BLOCKLIST ADD: {sel['name']}")
        self.status.set(f"Added {sel['name']} to blocklist.")
        self.refresh_all()

    def add_allowlist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        ALLOWLIST.add(sel["name"].lower())
        save_rules()
        self.add_log(f"ALLOWLIST ADD: {sel['name']}")
        self.status.set(f"Added {sel['name']} to allowlist.")
        self.refresh_all()

    def edit_rules_popup(self):
        win = tk.Toplevel(self)
        win.title("Edit Rules")
        win.geometry("400x260")

        ttk.Label(win, text="Auto-Kill Score ≥").pack(pady=(8, 2))
        kill_var = tk.StringVar(value=str(AUTO_KILL_RULES.get("high_threat_score", 90)))
        kill_entry = ttk.Entry(win, textvariable=kill_var)
        kill_entry.pack(pady=2)

        ttk.Label(win, text="Auto-Mute Score ≥").pack(pady=(8, 2))
        mute_var = tk.StringVar(value=str(AUTO_MUTE_RULES.get("medium_threat_score", 60)))
        mute_entry = ttk.Entry(win, textvariable=mute_var)
        mute_entry.pack(pady=2)

        def save():
            try:
                AUTO_KILL_RULES["high_threat_score"] = int(kill_var.get())
                AUTO_MUTE_RULES["medium_threat_score"] = int(mute_var.get())
                save_rules()
                self.add_log(f"RULES UPDATED: kill≥{AUTO_KILL_RULES['high_threat_score']} mute≥{AUTO_MUTE_RULES['medium_threat_score']}")
                win.destroy()
            except Exception:
                messagebox.showerror("Error", "Invalid values.")

        ttk.Button(win, text="Save", command=save).pack(pady=12)

def main():
    app = AudioWeaponConsole()
    app.mainloop()


if __name__ == "__main__":
    main()
