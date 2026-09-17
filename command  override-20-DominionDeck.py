import os
import sys
import json
import ctypes
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import winreg
import time
import threading

# OPTIONAL: shortcut support (pywin32)
try:
    import pythoncom
    import win32com.client
    HAS_SHORTCUT_SUPPORT = True
except ImportError:
    HAS_SHORTCUT_SUPPORT = False

CONFIG_FILE = "dominion_config.json"
BACKUP_FILE = "python_assoc_backup.json"

# 🔐 Admin check
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# 🔼 Relaunch with admin rights
def elevate():
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    sys.exit()

# 🖥 Get Desktop/DominionScripts folder
def get_dominion_folder():
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    return os.path.join(desktop, "DominionScripts")

# 📦 Backup registry keys
def backup_registry():
    keys_to_backup = [
        r"Python.File\shell\open\command",
        r"py_auto_file\shell\open\command",
        r"Applications\python.exe\shell\open\command",
    ]
    backup_data = {}
    for key_path in keys_to_backup:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CLASSES_ROOT, key_path, 0, winreg.KEY_READ
            ) as key:
                value, _ = winreg.QueryValueEx(key, "")
                backup_data[key_path] = value
        except FileNotFoundError:
            backup_data[key_path] = None
        except OSError:
            backup_data[key_path] = None

    with open(BACKUP_FILE, "w") as f:
        json.dump(backup_data, f, indent=2)

    return True

# ♻ Restore registry backup
def restore_registry():
    if not os.path.exists(BACKUP_FILE):
        return False

    with open(BACKUP_FILE, "r") as f:
        backup_data = json.load(f)

    for key_path, value in backup_data.items():
        try:
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
                if value is None:
                    try:
                        winreg.DeleteValue(key, "")
                    except Exception:
                        pass
                else:
                    winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)
        except Exception:
            pass

    return True

# 🛠 Install THIS file as system-wide Python handler
def install_handler():
    handler_path = os.path.abspath(sys.argv[0])
    command = f'"{handler_path}" "%1"'

    target_keys = [
        r"Python.File\shell\open\command",
        r"py_auto_file\shell\open\command",
        r"Applications\python.exe\shell\open\command",
    ]

    ok = True
    for key_path in target_keys:
        try:
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
        except Exception:
            ok = False

    return ok

# 💾 Save config
def save_config(handler_path, script_folder):
    data = {
        "handler": os.path.abspath(handler_path),
        "scripts": os.path.abspath(script_folder)
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return True

# ▶ Runner mode (when Windows calls this as handler with a .py argument)
def runner_mode(target_script):
    target_script = os.path.abspath(target_script)
    if not os.path.isfile(target_script):
        return
    try:
        subprocess.run([sys.executable, "-u", target_script])
    except Exception:
        pass

# 🔗 Resolve .lnk shortcut → target path
def resolve_shortcut(path):
    if not HAS_SHORTCUT_SUPPORT:
        return None
    try:
        pythoncom.CoInitialize()
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(path)
        return shortcut.TargetPath
    except Exception:
        return None

# 🧬 Auto‑script loader + watchdog (supports .py and .lnk)
class ScriptManager:
    def __init__(self, folder, log_callback):
        self.folder = folder
        self.log = log_callback
        self.processes = {}
        self.running = True

    def scan_and_start(self):
        if not os.path.isdir(self.folder):
            self.log("⚠ DominionScripts folder missing.")
            return

        for file in os.listdir(self.folder):
            full = os.path.join(self.folder, file)

            # REAL .py FILE
            if file.endswith(".py"):
                name = file
                if name not in self.processes:
                    self.start_script(name, full)

            # SHORTCUT .lnk FILE
            elif file.endswith(".lnk"):
                if not HAS_SHORTCUT_SUPPORT:
                    self.log(f"⚠ Shortcut support not available (pywin32 missing): {file}")
                    continue

                target = resolve_shortcut(full)
                if target and target.endswith(".py") and os.path.isfile(target):
                    name = f"{file} → {os.path.basename(target)}"
                    if name not in self.processes:
                        self.start_script(name, target)
                else:
                    self.log(f"⚠ Shortcut invalid or not a .py: {file}")

    def start_script(self, name, path):
        try:
            proc = subprocess.Popen([sys.executable, "-u", path])
            self.processes[name] = proc
            self.log(f"✔ Started: {name}")
        except Exception as e:
            self.log(f"⚠ Failed to start {name}: {e}")

    def watchdog(self):
        while self.running:
            time.sleep(3)
            for name, proc in list(self.processes.items()):
                if proc.poll() is not None:
                    self.log(f"⚠ {name} crashed — restarting...")
                    # For .py directly in folder
                    if "→" not in name:
                        full = os.path.join(self.folder, name)
                        if os.path.isfile(full):
                            self.start_script(name, full)
                        else:
                            self.log(f"⚠ Cannot restart {name}, file missing.")
                    else:
                        # For shortcuts, we re-resolve the shortcut
                        shortcut_name = name.split("→", 1)[0].strip()
                        shortcut_path = os.path.join(self.folder, shortcut_name)
                        target = resolve_shortcut(shortcut_path)
                        if target and target.endswith(".py") and os.path.isfile(target):
                            self.start_script(name, target)
                        else:
                            self.log(f"⚠ Cannot restart via shortcut: {name}")

    def stop_all(self):
        self.running = False
        for name, proc in self.processes.items():
            try:
                proc.terminate()
            except Exception:
                pass

class AutoDominionDeck(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡 Auto DominionDeck Installer & Handler")
        self.geometry("700x500")
        self.resizable(False, False)

        self.status_lines = []
        self.script_manager = None

        self.build_ui()
        self.after(100, self.auto_setup)

    def log(self, msg):
        self.status_lines.append(msg)
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", tk.END)
        self.status_text.insert(tk.END, "\n".join(self.status_lines))
        self.status_text.configure(state="disabled")
        self.status_text.see(tk.END)

    def build_ui(self):
        main = ttk.Frame(self)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        title = ttk.Label(
            main,
            text="DominionDeck Auto Installer & Python Handler",
            font=("Consolas", 16),
        )
        title.pack(pady=5)

        status_frame = ttk.LabelFrame(main, text="Status")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.status_text = tk.Text(status_frame, height=15, wrap="word")
        self.status_text.pack(fill=tk.BOTH, expand=True)
        self.status_text.configure(state="disabled")

        btn_frame = ttk.Frame(main)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="🧷 Force Backup", command=self.gui_backup).grid(
            row=0, column=0, padx=10
        )
        ttk.Button(btn_frame, text="♻ Force Restore", command=self.gui_restore).grid(
            row=0, column=1, padx=10
        )
        ttk.Button(btn_frame, text="🛠 Reinstall Handler", command=self.gui_install).grid(
            row=0, column=2, padx=10
        )
        ttk.Button(btn_frame, text="🚪 Exit", command=self.exit_app).grid(
            row=0, column=3, padx=10
        )

    def auto_setup(self):
        dom_folder = get_dominion_folder()
        try:
            os.makedirs(dom_folder, exist_ok=True)
            self.log(f"✔ DominionScripts folder: {dom_folder}")
        except Exception as e:
            self.log(f"⚠ Failed to create DominionScripts folder: {e}")

        # 1) Backup registry
        try:
            backup_registry()
            self.log("✔ Registry backup created")
        except Exception as e:
            self.log(f"⚠ Registry backup failed: {e}")

        # 2) Install handler
        try:
            ok = install_handler()
            if ok:
                self.log("✔ Installed as system-wide Python handler")
            else:
                self.log("⚠ Failed to install handler")
        except Exception as e:
            self.log(f"⚠ Handler install error: {e}")

        # 3) Restore registry (forces Windows to refresh associations)
        try:
            ok = restore_registry()
            if ok:
                self.log("✔ Registry restored from backup (cache flush)")
            else:
                self.log("⚠ Registry restore failed or no backup found")
        except Exception as e:
            self.log(f"⚠ Registry restore error: {e}")

        # 4) Save config
        try:
            save_config(os.path.abspath(sys.argv[0]), dom_folder)
            self.log("✔ Config saved")
        except Exception as e:
            self.log(f"⚠ Failed to save config: {e}")

        # 5) AUTO‑SCRIPT LOADING (.py + .lnk)
        self.script_manager = ScriptManager(dom_folder, self.log)
        self.script_manager.scan_and_start()

        t = threading.Thread(target=self.script_manager.watchdog, daemon=True)
        t.start()

        if HAS_SHORTCUT_SUPPORT:
            self.log("🔥 Shortcut support enabled (.lnk → .py).")
        else:
            self.log("⚠ Shortcut support disabled (install pywin32 for .lnk support).")

        self.log("🔥 Auto‑script loading active.")
        self.log("🔥 Watchdog active.")
        self.log("✅ System fully initialized.")

    def gui_backup(self):
        try:
            backup_registry()
            self.log("✔ Manual registry backup created")
            messagebox.showinfo("Backup", "Registry backup created.")
        except Exception as e:
            self.log(f"⚠ Manual backup failed: {e}")
            messagebox.showerror("Backup Error", str(e))

    def gui_restore(self):
        try:
            ok = restore_registry()
            if ok:
                self.log("✔ Registry restored from backup")
                messagebox.showinfo("Restore", "Registry restored from backup.")
            else:
                self.log("⚠ No backup found or restore failed")
                messagebox.showerror("Restore", "No backup found or restore failed.")
        except Exception as e:
            self.log(f"⚠ Restore error: {e}")
            messagebox.showerror("Restore Error", str(e))

    def gui_install(self):
        try:
            ok = install_handler()
            if ok:
                self.log("✔ Reinstalled as system-wide Python handler")
                messagebox.showinfo("Install", "Handler reinstalled.")
            else:
                self.log("⚠ Failed to reinstall handler")
                messagebox.showerror("Install", "Failed to reinstall handler.")
        except Exception as e:
            self.log(f"⚠ Install error: {e}")
            messagebox.showerror("Install Error", str(e))

    def exit_app(self):
        if self.script_manager:
            self.script_manager.stop_all()
        self.destroy()

if __name__ == "__main__":
    # If called with a .py argument → runner mode
    if len(sys.argv) > 1 and sys.argv[1].lower().endswith(".py"):
        runner_mode(sys.argv[1])
        sys.exit(0)

    # Normal mode → auto installer + GUI
    if not is_admin():
        elevate()

    app = AutoDominionDeck()
    app.mainloop()
