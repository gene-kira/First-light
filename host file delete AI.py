import os
import sys
import ctypes
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext

HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

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
        self.root.title("Windows Hosts File Manager (Manual & AI Ready)")
        self.root.geometry("650x500")
        
        # UI Header
        self.label = tk.Label(root, text="Windows Hosts File Controller", font=("Arial", 14, "bold"))
        self.label.pack(pady=10)
        
        # Text Area to view the hosts file
        self.text_area = scrolledtext.ScrolledText(root, width=75, height=20, font=("Consolas", 10))
        self.text_area.pack(padx=10, pady=5)
        
        # Button Frame (Manual Controls)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        
        self.btn_refresh = tk.Button(btn_frame, text="Load/Refresh File", command=self.load_hosts_content, width=15)
        self.btn_refresh.grid(row=0, column=0, padx=5)
        
        self.btn_delete = tk.Button(btn_frame, text="Clear/Delete Content", command=self.manual_clear_hosts, bg="#ffcccc", width=18)
        self.btn_delete.grid(row=0, column=1, padx=5)
        
        self.btn_ai_sim = tk.Button(btn_frame, text="Trigger AI Auto-Clear", command=self.simulate_ai_trigger, bg="#ccffcc", width=18)
        self.btn_ai_sim.grid(row=0, column=2, padx=5)

        # Load file contents on startup
        self.load_hosts_content()

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
        """
        Backend function meant to be called automatically by an AI script, 
        webhook, or automation routine.
        """
        if not os.path.exists(HOSTS_PATH):
            return {"status": "error", "message": "Hosts file does not exist."}
        
        try:
            # 1. Create a safety backup first
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{HOSTS_PATH}.{timestamp}.bak"
            shutil.copy2(HOSTS_PATH, backup_path)
            
            # 2. Clear out the contents (effectively resets/deletes entries)
            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write("# Hosts file cleared or reset automatically\n")
                
            return {"status": "success", "backup": backup_path}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def manual_clear_hosts(self):
        """Manual button action wrapper for clearing the hosts file with prompts."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear/reset the hosts file? A backup will be made."):
            result = self.ai_delete_hosts_file()
            if result["status"] == "success":
                messagebox.showinfo("Success", f"Hosts file cleared successfully!\nBackup saved to:\n{result['backup']}")
                self.load_hosts_content()
            else:
                messagebox.showerror("Error", f"Failed to modify hosts file: {result['message']}")

    def simulate_ai_trigger(self):
        """Simulates an AI agent automatically deciding and executing the hosts clearance."""
        if messagebox.askyesno("AI Automation Simulation", "Allow AI agent to take automated control and clear the hosts file now?"):
            result = self.ai_delete_hosts_file()
            if result["status"] == "success":
                messagebox.println = messagebox.showinfo("AI Action Complete", f"AI successfully cleared the hosts file.\nBackup: {result['backup']}")
                self.load_hosts_content()
            else:
                messagebox.showerror("AI Error", f"AI action failed: {result['message']}")

if __name__ == "__main__":
    # Ensure execution requires and has Windows Admin Rights
    if not is_admin():
        print("Requesting administrative privileges...")
        run_as_admin()
    
    root = tk.Tk()
    app = HostsManagerApp(root)
    root.mainloop()