import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import pythoncom
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
from datetime import datetime


LOG_FILE = "audio_network_log.txt"


def write_log(message):
    """Append message to log file."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    return line


class AudioNetworkViewer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Audio + Network Connection Viewer — Manual Kill Console")
        self.geometry("1300x650")

        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(top, text="Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=5)

        self.tree = ttk.Treeview(
            self,
            columns=("pid", "name", "volume", "muted", "ip", "port"),
            show="headings",
            height=18
        )

        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Process")
        self.tree.heading("volume", text="Volume")
        self.tree.heading("muted", text="Muted")
        self.tree.heading("ip", text="Remote IP")
        self.tree.heading("port", text="Port")

        self.tree.column("pid", width=80, anchor=tk.CENTER)
        self.tree.column("name", width=250, anchor=tk.W)
        self.tree.column("volume", width=80, anchor=tk.CENTER)
        self.tree.column("muted", width=80, anchor=tk.CENTER)
        self.tree.column("ip", width=250, anchor=tk.CENTER)
        self.tree.column("port", width=80, anchor=tk.CENTER)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # === LOG WINDOW ===
        log_frame = ttk.LabelFrame(self, text="Running Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_box = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(bottom, text="Kill Selected Process", command=self.kill_selected).pack(side=tk.LEFT, padx=5)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT, padx=10)

    def add_log(self, message):
        """Add message to GUI log + file."""
        line = write_log(message)
        self.log_box.insert(tk.END, line)
        self.log_box.see(tk.END)

    def refresh_all(self):
        pythoncom.CoInitialize()
        sessions = AudioUtilities.GetAllSessions()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.add_log("Refreshing audio + network list...")

        for session in sessions:
            try:
                volume = session._ctl.QueryInterface(ISimpleAudioVolume)
                vol_level = volume.GetMasterVolume()
                muted = volume.GetMute()

                pid = session.Process.pid if session.Process else None
                name = session.Process.name() if session.Process else "System"

                vol_str = f"{int(vol_level * 100)}%"
                muted_str = "Yes" if muted else "No"

                ip_list = []
                port_list = []

                if pid is not None:
                    try:
                        proc = psutil.Process(pid)
                        conns = proc.connections(kind="inet")

                        for c in conns:
                            if c.raddr:
                                ip_list.append(c.raddr.ip)
                                port_list.append(c.raddr.port)
                    except Exception:
                        pass

                if not ip_list:
                    ip_list = ["-"]
                    port_list = ["-"]

                for ip, port in zip(ip_list, port_list):
                    self.tree.insert(
                        "",
                        tk.END,
                        values=(pid, name, vol_str, muted_str, ip, port)
                    )

                    self.add_log(f"Audio PID={pid} Name={name} Vol={vol_str} IP={ip} Port={port}")

            except Exception:
                continue

        self.status.set("Audio + network refreshed")

    def kill_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No selection", "Select a process first.")
            return

        item = self.tree.item(selected[0])
        pid = item["values"][0]
        name = item["values"][1]

        if pid is None:
            messagebox.showwarning("Cannot kill", "This audio session has no PID.")
            return

        answer = messagebox.askyesno(
            "Confirm Kill",
            f"Kill process {name} (PID {pid})?"
        )
        if not answer:
            return

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=3)
            for p in alive:
                p.kill()

            self.add_log(f"KILLED PID={pid} Name={name}")
            self.status.set(f"Killed {name} (PID {pid})")
            self.refresh_all()

        except Exception as e:
            self.add_log(f"Kill FAILED PID={pid} Error={e}")
            messagebox.showerror("Error", f"Failed to kill process: {e}")
            self.status.set(f"Kill error: {e}")


def main():
    app = AudioNetworkViewer()
    app.mainloop()


if __name__ == "__main__":
    main()
