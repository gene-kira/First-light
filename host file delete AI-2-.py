import os
import sys
import json
import ctypes
import shutil
import winreg
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts_manager_config.json")
REG_APP_NAME = "WindowsHostsManagerAI"

def is_admin():
    """Check if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Relaunch the current script with administrator privileges."""
    script = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to elevate to Administrator: {e}")
    sys.exit()

class HostsManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Hosts Manager (Persistent & Auto-Start)")
        self.root.geometry("680x600")
        
        self.automation_active = False
        self.after_id = None

        # Load saved settings
        self.config = self.load_config()

        # UI Header
        self.label = tk.Label(root, text="Windows Hosts File Controller (Persistent Settings)", font=("Arial", 14, "bold"))
        self.label.pack(pady=10)
        
        # Text Area to view the hosts file
        self.text_area = scrolledtext.ScrolledText(root, width=78, height=14, font=("Consolas", 10))
        self.text_area.pack(padx=10, pady=5)
        
        # Manual Control Button Frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=8)
        
        self.btn_refresh = tk.Button(btn_frame, text="Load/Refresh File", command=self.load_hosts_content, width=16)
        self.btn_refresh.grid(row=0, column=0, padx=5)
        
        self.btn_delete = tk.Button(btn_frame, text="Clear Content Now", command=self.manual_clear_hosts, bg="#ffcccc", width=18)
        self.btn_delete.grid(row=0, column=1, padx=5)

        # Automation / Timed Loop Configuration Frame
        auto_frame = ttk.LabelFrame(root, text=" Background Automation & Persistence ", padding=10)
        auto_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(auto_frame, text="Interval (seconds):").grid(row=0, column=0, sticky="w", padx=5)
        
        self.interval_var = tk.StringVar(value=str(self.config.get("interval", 60)))
        self.interval_entry = tk.Entry(auto_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=0, column=1, sticky="w", padx=5)

        self.btn_toggle_auto = tk.Button(auto_frame, text="Start Timed Loop", command=self.toggle_automation, bg="#ccffcc", width=18)
        self.btn_toggle_auto.grid(row=0, column=2, padx=15)

        # Checkboxes for persistence
        self.startup_var = tk.BooleanVar(value=self.check_windows_startup())
        self.chk_startup = tk.Checkbutton(auto_frame, text="Run automatically on Windows Startup", variable=self.startup_var, command=self.toggle_windows_startup)
        self.chk_startup.grid(row=1, column=0, columnspan=3, sticky="w", padx=5, pady=(8, 2))

        self.autoresume_var = tk.BooleanVar(value=self.config.get("auto_resume", False))
        self.chk_autoresume = tk.Checkbutton(auto_frame, text="Auto-resume timed loop upon app launch/reboot", variable=self.autoresume_var, command=self.save_current_config)
        self.chk_autoresume.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=(2, 2))

        self.status_label = tk.Label(auto_frame, text="Status: Automation is OFF", fg="gray", font=("Arial", 9, "italic"))
        self.status_label.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=(8, 0))

        # Load file contents on startup
        self.load_hosts_content()

        # Check if we should auto-resume automation upon boot/launch
        if self.config.get("was_running", False) and self.autoresume_var.get():
            self.root.after(1000, self.auto_start_loop)

    def load_config(self):
        """Load persistent configuration from JSON file."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"interval": 60, "was_running": False, "auto_resume": False}

    def save_current_config(self):
        """Save current user settings to JSON config file."""
        try:
            interval = int(self.interval_var.get())
        except ValueError:
            interval = 60

        config_data = {
            "interval": interval,
            "was_running": self.automation_active,
            "auto_resume": self.autoresume_var.get()
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config_data, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def check_windows_startup(self):
        """Check if script is currently registered in Windows Registry Startup."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            winreg.QueryValueEx(key, REG_APP_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False

    def toggle_windows_startup(self):
        """Add or remove script from Windows Registry Startup."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            script_path = os.path.abspath(sys.argv[0])
            # Wrap python script execution command safely
            cmd = f'"{sys.executable}" "{script_path}"'
            
            if self.startup_var.get():
                winreg.SetValueEx(key, REG_APP_NAME, 0, winreg.REG_SZ, cmd)
                messagebox.showinfo("Startup Enabled", "The application has been registered to start automatically when Windows boots.")
            else:
                try:
                    winreg.DeleteValue(key, REG_APP_NAME)
                    messagebox.showinfo("Startup Disabled", "The application has been removed from Windows startup.")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
        except Exception as e:
            messagebox.showerror("Registry Error", f"Failed to modify Windows startup registry: {e}")
            self.startup_var.set(not self.startup_var.get()) # Revert checkbox

    def load_hosts_content(self):
        """Reads and displays the current hosts file content."""
        self.text_area.delete("1.0", tk.END)
        if os.path.exists(HOSTS_PATH):
            try:
                with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    self.text_area.insert(tk.END, content)
            except Exception as e:
                self.text_area.insert(tk.END, f"Error reading hosts file: {e}")
        else:
            self.text_area.insert(tk.END, "Hosts file not found at default location.")

    def ai_delete_hosts_file(self):
        """Backend function that creates a backup and clears the hosts file."""
        if not os.path.exists(HOSTS_PATH):
            return {"status": "error", "message": "Hosts file does not exist."}
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{HOSTS_PATH}.{timestamp}.bak"
            shutil.copy2(HOSTS_PATH, backup_path)
            
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write(f"# Hosts file cleared automatically on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
            return {"status": "success", "backup": backup_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def manual_clear_hosts(self):
        """Manual button action wrapper for clearing the hosts file with confirmation prompts."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear/reset the hosts file? A backup will be made."):
            result = self.ai_delete_hosts_file()
            if result["status"] == "success":
                messagebox.showinfo("Success", f"Hosts file cleared successfully!\nBackup saved to:\n{result['backup']}")
                self.load_hosts_content()
            else:
                messagebox.showerror("Error", f"Failed to modify hosts file: {result['message']}")

    def toggle_automation(self):
        """Starts or stops the background timed automation loop."""
        if not self.automation_active:
            try:
                interval_sec = int(self.interval_var.get())
                if interval_sec < 5:
                    messagebox.showwarning("Invalid Interval", "Interval must be at least 5 seconds.")
                    return
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid integer for seconds.")
                return

            self.automation_active = True
            self.btn_toggle_auto.config(text="Stop Timed Loop", bg="#ffcccc")
            self.interval_entry.config(state="disabled")
            self.status_label.config(text=f"Status: Running (Clears every {interval_sec}s)", fg="green")
            
            self.save_current_config()
            self.run_scheduled_clear(interval_sec)
        else:
            self.automation_active = False
            if self.after_id:
                self.root.after_cancel(self.after_id)
                self.after_id = None
            
            self.btn_toggle_auto.config(text="Start Timed Loop", bg="#ccffcc")
            self.interval_entry.config(state="normal")
            self.status_label.config(text="Status: Automation is OFF", fg="gray")
            self.save_current_config()

    def auto_start_loop(self):
        """Automatically triggers the loop upon reboot/launch if saved as active."""
        try:
            interval_sec = int(self.interval_var.get())
        except ValueError:
            interval_sec = 60

        self.automation_active = True
        self.btn_toggle_auto.config(text="Stop Timed Loop", bg="#ffcccc")
        self.interval_entry.config(state="disabled")
        self.status_label.config(text=f"Status: Auto-resumed (Clears every {interval_sec}s)", fg="green")
        self.run_scheduled_clear(interval_sec)

    def run_scheduled_clear(self, interval_sec):
        """Executes the clear action on the timed loop and schedules the next iteration."""
        if not self.automation_active:
            return

        result = self.ai_delete_hosts_file()
        if result["status"] == "success":
            self.load_hosts_content()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Automated background clear successful. Backup: {result['backup']}")

        if self.automation_active:
            self.after_id = self.root.after(interval_sec * 1000, lambda: self.run_scheduled_clear(interval_sec))

if __name__ == "__main__":
    if not is_admin():
        print("Requesting administrative privileges...")
        run_as_admin()
    
    root = tk.Tk()
    app = HostsManagerApp(root)
    root.mainloop()