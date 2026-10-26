#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Windows GodMode Control Center — Enhanced Edition
Features:
- Right-side vertical scrollbar and bottom horizontal scrollbar for Services
- Search, status filters, sortable columns, multi-column layout
- Optional auto-refresh with configurable interval
- Service details/status bar, safe stop confirmation, refresh/error handling
- Start/stop/pause/resume actions
- Searchable system panels with launch error handling

Requirements: Windows + pywin32
Install if needed: py -m pip install pywin32
"""

import os
import sys
import time
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import win32service
    import win32serviceutil
except ImportError:
    win32service = None
    win32serviceutil = None


SYSTEM_PANELS = {
    "Control Panel": "control.exe",
    "System Properties": "SystemPropertiesAdvanced.exe",
    "Device Manager": "devmgmt.msc",
    "Disk Management": "diskmgmt.msc",
    "Event Viewer": "eventvwr.msc",
    "Local Group Policy Editor": "gpedit.msc",
    "Services Manager": "services.msc",
    "Network Connections": "ncpa.cpl",
    "Firewall Settings": "firewall.cpl",
    "Power Options": "powercfg.cpl",
    "Programs & Features": "appwiz.cpl",
    "Date & Time": "timedate.cpl",
    "Mouse Settings": "main.cpl",
    "Keyboard Settings": "control keyboard",
    "Display Settings": "desk.cpl",
    "User Accounts": "nusrmgr.cpl",
    "Windows Update": "control update",
}

STATUS_NAMES = {
    1: "Stopped",
    2: "Start Pending",
    3: "Stop Pending",
    4: "Running",
    5: "Continue Pending",
    6: "Pause Pending",
    7: "Paused",
}


def get_status_text(state):
    if win32service is not None:
        names = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Start Pending",
            win32service.SERVICE_STOP_PENDING: "Stop Pending",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
            win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
            win32service.SERVICE_PAUSED: "Paused",
        }
        if state in names:
            return names[state]
    return STATUS_NAMES.get(state, f"State {state}")


def list_services():
    """Enumerate Windows services and always close the service-manager handle."""
    if win32service is None:
        raise RuntimeError(
            "The pywin32 package is missing.\n\nInstall it with:\n"
            "py -m pip install pywin32"
        )

    services = []
    scm = None
    try:
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
        )
        statuses = win32service.EnumServicesStatus(scm)
        for service_name, display_name, status in statuses:
            services.append({
                "service_name": service_name,
                "display_name": display_name,
                "current_state": status[1],
            })
    finally:
        if scm is not None:
            try:
                win32service.CloseServiceHandle(scm)
            except Exception:
                pass
    return sorted(services, key=lambda item: item["display_name"].casefold())


def launch_panel(command):
    """Launch a Windows control panel or MMC snap-in without shell=True."""
    try:
        if command.startswith("control "):
            subprocess.Popen(["control.exe", command[len("control "):]])
        else:
            # MMC snap-ins and Windows executables are passed as a single argument.
            subprocess.Popen([command], shell=False)
    except FileNotFoundError:
        messagebox.showerror(
            "Panel unavailable",
            f"Windows could not find or launch:\n{command}\n\n"
            "Some panels (such as Local Group Policy Editor) are not included "
            "in every Windows edition."
        )
    except Exception as exc:
        messagebox.showerror("Error launching panel", str(exc))


class GodModeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows GodMode Control Center — Enhanced")
        self.root.geometry("1050x650")
        self.root.minsize(760, 460)

        self.all_services = []
        self._refresh_job = None
        self._busy = False
        self.sort_reverse = {}
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="All")
        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.refresh_interval_var = tk.StringVar(value="10")
        self.panel_search_var = tk.StringVar()

        self._build_menu()
        self._build_ui()
        self.load_services()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_menu(self):
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Refresh Services", command=self.load_services)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menu.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menu)

    def _build_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        self.services_frame = ttk.Frame(self.notebook, padding=8)
        self.panels_frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.services_frame, text="Services")
        self.notebook.add(self.panels_frame, text="System Panels")

        self._build_services_tab()
        self._build_panels_tab()

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(
            self.root, textvariable=self.status_var, anchor="w", relief="sunken"
        )
        status.pack(fill="x", side="bottom", padx=8, pady=(0, 8))

    def _build_services_tab(self):
        toolbar = ttk.Frame(self.services_frame)
        toolbar.pack(fill="x", pady=(0, 7))

        ttk.Label(toolbar, text="Search:").pack(side="left")
        search = ttk.Entry(toolbar, textvariable=self.search_var, width=26)
        search.pack(side="left", padx=(5, 12))
        search.bind("<KeyRelease>", lambda _event: self.refresh_services())

        ttk.Label(toolbar, text="Status:").pack(side="left")
        filter_box = ttk.Combobox(
            toolbar, textvariable=self.filter_var,
            values=["All", "Running", "Stopped", "Paused", "Pending"],
            width=12, state="readonly"
        )
        filter_box.pack(side="left", padx=(5, 12))
        filter_box.bind("<<ComboboxSelected>>", lambda _event: self.refresh_services())

        ttk.Button(toolbar, text="Refresh Now", command=self.load_services).pack(
            side="left", padx=(0, 12)
        )

        ttk.Checkbutton(
            toolbar, text="Auto-refresh",
            variable=self.auto_refresh_var, command=self.toggle_auto_refresh
        ).pack(side="left")
        ttk.Label(toolbar, text="Every").pack(side="left", padx=(8, 3))
        interval = ttk.Combobox(
            toolbar, textvariable=self.refresh_interval_var,
            values=["5", "10", "15", "30", "60"], width=4, state="readonly"
        )
        interval.pack(side="left")
        ttk.Label(toolbar, text="sec").pack(side="left", padx=(3, 0))
        interval.bind("<<ComboboxSelected>>", lambda _event: self._reschedule_refresh())

        table_frame = ttk.Frame(self.services_frame)
        table_frame.pack(fill="both", expand=True)

        columns = ("service_name", "display_name", "status")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse"
        )
        self.tree.heading(
            "service_name", text="Service Name",
            command=lambda: self.sort_services("service_name")
        )
        self.tree.heading(
            "display_name", text="Display Name",
            command=lambda: self.sort_services("display_name")
        )
        self.tree.heading(
            "status", text="Status",
            command=lambda: self.sort_services("status")
        )
        self.tree.column("service_name", width=245, minwidth=150, anchor="w")
        self.tree.column("display_name", width=420, minwidth=180, anchor="w")
        self.tree.column("status", width=135, minwidth=110, anchor="center")

        # The vertical scrollbar is deliberately placed on the RIGHT of the service list.
        vertical_scroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree.yview
        )
        horizontal_scroll = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set
        )

        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical_scroll.grid(row=0, column=1, sticky="ns")
        horizontal_scroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("running", background="#e5f6e8")
        self.tree.tag_configure("stopped", background="#fde8e7")
        self.tree.tag_configure("paused", background="#fff4d6")
        self.tree.tag_configure("pending", background="#eaf1ff")
        self.tree.bind("<<TreeviewSelect>>", self.on_service_select)
        self.tree.bind("<Double-1>", lambda _event: self.show_selected_details())

        controls = ttk.Frame(self.services_frame)
        controls.pack(fill="x", pady=(8, 0))

        for label, callback in [
            ("Start", self.action_start),
            ("Stop", self.action_stop),
            ("Pause", self.action_pause),
            ("Resume", self.action_resume),
            ("Details", self.show_selected_details),
        ]:
            ttk.Button(controls, text=label, command=callback).pack(
                side="left", padx=(0, 6)
            )

        self.count_var = tk.StringVar(value="0 services")
        ttk.Label(controls, textvariable=self.count_var).pack(side="right", padx=5)

    def _build_panels_tab(self):
        top = ttk.Frame(self.panels_frame)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Find a panel:").pack(side="left")
        entry = ttk.Entry(top, textvariable=self.panel_search_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<KeyRelease>", lambda _event: self.refresh_panels())

        self.panel_list = ttk.Frame(self.panels_frame)
        self.panel_list.pack(fill="both", expand=True)

        self.panel_canvas = tk.Canvas(self.panel_list, highlightthickness=0)
        panel_scroll = ttk.Scrollbar(
            self.panel_list, orient="vertical", command=self.panel_canvas.yview
        )
        self.panel_inner = ttk.Frame(self.panel_canvas)
        self.panel_window = self.panel_canvas.create_window(
            (0, 0), window=self.panel_inner, anchor="nw"
        )
        self.panel_inner.bind(
            "<Configure>",
            lambda _event: self.panel_canvas.configure(
                scrollregion=self.panel_canvas.bbox("all")
            )
        )
        self.panel_canvas.bind(
            "<Configure>",
            lambda event: self.panel_canvas.itemconfigure(
                self.panel_window, width=event.width
            )
        )
        self.panel_canvas.configure(yscrollcommand=panel_scroll.set)
        self.panel_canvas.pack(side="left", fill="both", expand=True)
        panel_scroll.pack(side="right", fill="y")
        self.refresh_panels()

    def refresh_panels(self):
        for child in self.panel_inner.winfo_children():
            child.destroy()
        term = self.panel_search_var.get().strip().casefold()
        matches = [
            (name, command) for name, command in SYSTEM_PANELS.items()
            if not term or term in name.casefold() or term in command.casefold()
        ]
        for index, (name, command) in enumerate(matches):
            row = ttk.Frame(self.panel_inner)
            row.pack(fill="x", pady=2)
            ttk.Button(
                row, text=name, command=lambda c=command: launch_panel(c)
            ).pack(side="left", fill="x", expand=True)
            ttk.Label(row, text=command).pack(side="left", padx=10)
        if not matches:
            ttk.Label(self.panel_inner, text="No matching panels.").pack(
                anchor="w", pady=10
            )

    def load_services(self):
        if self._busy:
            return
        self._busy = True
        self.status_var.set("Loading Windows services…")
        try:
            self.all_services = list_services()
            self.refresh_services()
            self.status_var.set(
                f"Loaded {len(self.all_services)} services at "
                f"{time.strftime('%H:%M:%S')}"
            )
        except Exception as exc:
            self.status_var.set("Could not load services.")
            messagebox.showerror("Service enumeration failed", str(exc))
        finally:
            self._busy = False

    def refresh_services(self):
        if not hasattr(self, "tree"):
            return
        selected_name = None
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0], "values")
            if values:
                selected_name = values[0]

        for item in self.tree.get_children():
            self.tree.delete(item)

        term = self.search_var.get().strip().casefold()
        mode = self.filter_var.get()
        visible = 0
        for service in self.all_services:
            name = service["service_name"]
            display = service["display_name"]
            state = service["current_state"]
            status = get_status_text(state)

            if term and term not in name.casefold() and term not in display.casefold():
                continue
            if mode == "Running" and status != "Running":
                continue
            if mode == "Stopped" and status != "Stopped":
                continue
            if mode == "Paused" and status != "Paused":
                continue
            if mode == "Pending" and "Pending" not in status:
                continue

            tag = (
                "running" if status == "Running" else
                "stopped" if status == "Stopped" else
                "paused" if status == "Paused" else "pending"
            )
            item = self.tree.insert(
                "", "end", values=(name, display, status), tags=(tag,)
            )
            if name == selected_name:
                self.tree.selection_set(item)
                self.tree.focus(item)
            visible += 1

        self.count_var.set(f"{visible} shown / {len(self.all_services)} total")

    def sort_services(self, column):
        reverse = self.sort_reverse.get(column, False)
        items = list(self.tree.get_children(""))
        items.sort(
            key=lambda item: str(self.tree.set(item, column)).casefold(),
            reverse=reverse
        )
        for index, item in enumerate(items):
            self.tree.move(item, "", index)
        self.sort_reverse[column] = not reverse

    def get_selected_service(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning(
                "Select a service", "Select a service from the list first."
            )
            return None
        values = self.tree.item(selected[0], "values")
        return values[0] if values else None

    def on_service_select(self, _event=None):
        name = self.get_selected_service_silent()
        if name:
            self.status_var.set(f"Selected service: {name}")

    def get_selected_service_silent(self):
        selected = self.tree.selection()
        if not selected:
            return None
        values = self.tree.item(selected[0], "values")
        return values[0] if values else None

    def show_selected_details(self):
        name = self.get_selected_service()
        if not name:
            return
        service = next(
            (item for item in self.all_services if item["service_name"] == name),
            None
        )
        if service:
            messagebox.showinfo(
                "Service Details",
                f"Display name: {service['display_name']}\n"
                f"Service name: {service['service_name']}\n"
                f"Current state: {get_status_text(service['current_state'])}\n\n"
                "Windows may require administrator rights to change this service."
            )

    def _run_service_action(self, action, verb, confirm=False):
        name = self.get_selected_service()
        if not name:
            return
        if confirm and not messagebox.askyesno(
            f"Confirm {verb}", f"Stop the service '{name}'?\n\n"
            "Stopping a Windows service can affect applications or system features."
        ):
            return
        try:
            if win32serviceutil is None:
                raise RuntimeError("pywin32 is not installed.")
            action(name)
            self.status_var.set(f"Requested {verb.lower()} for {name}.")
            # Service state transitions can take a moment; refresh shortly.
            self.root.after(900, self.load_services)
        except Exception as exc:
            messagebox.showerror(f"Could not {verb.lower()} service", f"{name}\n\n{exc}")
            self.status_var.set(f"{verb} failed for {name}.")

    def action_start(self):
        self._run_service_action(win32serviceutil.StartService if win32serviceutil else None, "Start")

    def action_stop(self):
        self._run_service_action(win32serviceutil.StopService if win32serviceutil else None, "Stop", confirm=True)

    def action_pause(self):
        self._run_service_action(win32serviceutil.PauseService if win32serviceutil else None, "Pause")

    def action_resume(self):
        self._run_service_action(win32serviceutil.ResumeService if win32serviceutil else None, "Resume")

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            self._reschedule_refresh()
            self.status_var.set("Auto-refresh enabled.")
        else:
            if self._refresh_job is not None:
                self.root.after_cancel(self._refresh_job)
                self._refresh_job = None
            self.status_var.set("Auto-refresh disabled.")

    def _reschedule_refresh(self):
        if self._refresh_job is not None:
            try:
                self.root.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        if self.auto_refresh_var.get():
            self._refresh_job = self.root.after(
                max(5, int(self.refresh_interval_var.get() or "10")) * 1000,
                self._auto_refresh_tick
            )

    def _auto_refresh_tick(self):
        self._refresh_job = None
        if not self.auto_refresh_var.get():
            return
        self.load_services()
        self._reschedule_refresh()

    def show_about(self):
        messagebox.showinfo(
            "About",
            "Windows GodMode Control Center — Enhanced Edition\n\n"
            "Browse and filter services, inspect status, control supported service "
            "states, and launch common Windows system panels.\n\n"
            "Run with appropriate Windows permissions for service control."
        )

    def on_close(self):
        if self._refresh_job is not None:
            try:
                self.root.after_cancel(self._refresh_job)
            except Exception:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = GodModeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
