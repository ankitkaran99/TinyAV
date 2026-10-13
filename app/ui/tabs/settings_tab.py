import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

import clamd
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.logger import get_default_log_dir, get_logger
from app.core.updater import UpdateManager
from app.platform_win.context_menu import (
    is_context_menu_registered,
    register_context_menu_elevated,
    unregister_context_menu_elevated,
)
from app.platform_win.startup import (
    disable_startup,
    enable_startup,
    is_startup_registered,
)

logger = get_logger()

class SettingsTab(ttk.Frame):
    def __init__(
        self,
        parent: ttk.Notebook,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        update_manager: UpdateManager,
        on_settings_saved: Callable[[], None],
    ):
        super().__init__(parent)
        self.config_manager = config_manager
        self.engine = engine
        self.update_manager = update_manager
        self.on_settings_saved = on_settings_saved

        self._build_ui()
        self.load_values()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)

        canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, padding=(12, 10))

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas_win = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_win, width=e.width))
        canvas.configure(yscrollcommand=scrollbar.set)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _: canvas.unbind_all("<MouseWheel>"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Section 1: ClamAV Paths & Daemon
        sec_clam = ttk.LabelFrame(scrollable_frame, text="ClamAV Engine Configuration", padding=(10, 8))
        sec_clam.pack(fill="x", expand=True, pady=6)
        sec_clam.columnconfigure(1, weight=1)

        ttk.Label(sec_clam, text="ClamAV Bin Directory:").grid(row=0, column=0, sticky="w", pady=4)
        self.bin_dir_var = tk.StringVar()
        self.bin_entry = ttk.Entry(sec_clam, textvariable=self.bin_dir_var)
        self.bin_entry.grid(row=0, column=1, sticky="ew", padx=6, pady=4)

        btn_box1 = ttk.Frame(sec_clam)
        btn_box1.grid(row=0, column=2, sticky="e", pady=4)
        ttk.Button(btn_box1, text="Browse...", command=self._browse_bin_dir).pack(side="left", padx=2)
        ttk.Button(btn_box1, text="Auto-Detect", command=self._auto_detect_bin).pack(side="left", padx=2)
        ttk.Button(btn_box1, text="Auto-Generate Conf Files", command=self._generate_configs).pack(side="left", padx=2)

        ttk.Label(sec_clam, text="clamd Host / Port:").grid(row=1, column=0, sticky="w", pady=4)
        hp_frame = ttk.Frame(sec_clam)
        hp_frame.grid(row=1, column=1, sticky="w", padx=6, pady=4)

        self.clamd_host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(hp_frame, textvariable=self.clamd_host_var, width=15).pack(side="left", padx=(0, 6))

        self.clamd_port_var = tk.IntVar(value=3310)
        ttk.Entry(hp_frame, textvariable=self.clamd_port_var, width=8).pack(side="left", padx=6)

        ttk.Button(hp_frame, text="Test clamd Socket", command=self._test_clamd).pack(side="left", padx=10)

        self.prefer_clamd_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sec_clam, text="Prefer clamd daemon over clamscan CLI", variable=self.prefer_clamd_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=4
        )

        # Section 2: Quarantine
        sec_quar = ttk.LabelFrame(scrollable_frame, text="Quarantine Vault Location", padding=(10, 8))
        sec_quar.pack(fill="x", expand=True, pady=6)
        sec_quar.columnconfigure(1, weight=1)

        ttk.Label(sec_quar, text="Quarantine Directory:").grid(row=0, column=0, sticky="w", pady=4)
        self.quar_dir_var = tk.StringVar()
        ttk.Entry(sec_quar, textvariable=self.quar_dir_var).grid(row=0, column=1, sticky="ew", padx=6, pady=4)
        ttk.Button(sec_quar, text="Browse...", command=self._browse_quar_dir).grid(row=0, column=2, sticky="e", pady=4)

        # Section 3: Definition Updates Schedule
        sec_upd = ttk.LabelFrame(scrollable_frame, text="Scheduled Virus Definition Updates", padding=(10, 8))
        sec_upd.pack(fill="x", expand=True, pady=6)

        self.auto_upd_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sec_upd, text="Enable periodic background updates with freshclam", variable=self.auto_upd_var).pack(anchor="w", pady=2)

        int_frame = ttk.Frame(sec_upd)
        int_frame.pack(anchor="w", pady=4)
        ttk.Label(int_frame, text="Update Interval:").pack(side="left", padx=(0, 6))
        self.interval_var = tk.IntVar(value=4)
        spin = ttk.Spinbox(int_frame, from_=1, to=48, textvariable=self.interval_var, width=5)
        spin.pack(side="left")
        ttk.Label(int_frame, text="hours").pack(side="left", padx=6)

        # Quick preset buttons for update interval
        preset_frame = ttk.Frame(sec_upd)
        preset_frame.pack(anchor="w", pady=(2, 4))
        ttk.Label(preset_frame, text="Presets:").pack(side="left", padx=(0, 6))
        for h in [1, 2, 4, 6, 12, 24]:
            ttk.Button(preset_frame, text=f"{h}h", width=4, command=lambda val=h: self.interval_var.set(val)).pack(side="left", padx=2)

        # Section 4: Real-Time Directory Monitoring (e.g. Downloads)
        sec_rt = ttk.LabelFrame(scrollable_frame, text="Real-Time Directory Monitoring (e.g. Downloads)", padding=(10, 8))
        sec_rt.pack(fill="x", expand=True, pady=6)

        self.rt_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sec_rt, text="Enable real-time background scanning for newly created files", variable=self.rt_enabled_var).pack(anchor="w", pady=2)

        self.rt_auto_quar_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sec_rt, text="Automatically quarantine threats detected in watched folders", variable=self.rt_auto_quar_var).pack(anchor="w", pady=2)

        ttk.Label(sec_rt, text="Watched Directories:").pack(anchor="w", pady=(6, 2))

        lb_frame = ttk.Frame(sec_rt)
        lb_frame.pack(fill="x", expand=True, pady=2)
        lb_frame.columnconfigure(0, weight=1)

        self.watched_listbox = tk.Listbox(lb_frame, height=4, selectmode="single")
        self.watched_listbox.grid(row=0, column=0, sticky="ew")

        lb_scroll = ttk.Scrollbar(lb_frame, orient="vertical", command=self.watched_listbox.yview)
        self.watched_listbox.configure(yscrollcommand=lb_scroll.set)
        lb_scroll.grid(row=0, column=1, sticky="ns")

        rt_btn_frame = ttk.Frame(sec_rt)
        rt_btn_frame.pack(anchor="w", pady=(6, 2))
        ttk.Button(rt_btn_frame, text="Add Downloads Folder", command=self._add_downloads_dir).pack(side="left", padx=(0, 4))
        ttk.Button(rt_btn_frame, text="Add Custom Folder...", command=self._add_custom_watched_dir).pack(side="left", padx=4)
        ttk.Button(rt_btn_frame, text="Remove Selected", command=self._remove_watched_dir).pack(side="left", padx=4)

        # Section 5: Windows Explorer & Auto-Start Integration
        sec_shell = ttk.LabelFrame(scrollable_frame, text="Windows Explorer & Auto-Start Integration", padding=(10, 8))
        sec_shell.pack(fill="x", expand=True, pady=6)

        status_row = ttk.Frame(sec_shell)
        status_row.pack(fill="x", pady=2)
        ttk.Label(status_row, text="'Scan with ClamAV' Right-Click Menu:").pack(side="left")
        self.shell_status_lbl = ttk.Label(status_row, text="Checking...", font=("Segoe UI", 9, "bold"))
        self.shell_status_lbl.pack(side="left", padx=8)

        btn_shell = ttk.Frame(sec_shell)
        btn_shell.pack(anchor="w", pady=6)
        ttk.Button(btn_shell, text="Register Context Menu (UAC)", command=self._register_shell).pack(side="left", padx=(0, 6))
        ttk.Button(btn_shell, text="Unregister Context Menu (UAC)", command=self._unregister_shell).pack(side="left", padx=6)

        ttk.Separator(sec_shell, orient="horizontal").pack(fill="x", pady=6)

        startup_row = ttk.Frame(sec_shell)
        startup_row.pack(fill="x", pady=2)
        self.startup_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            startup_row,
            text="Launch TinyAV automatically at Windows login (Silent tray, zero console windows)",
            variable=self.startup_var,
            command=self._on_startup_toggle,
        ).pack(side="left")

        # Section 6: Removable Drives & Logs
        sec_misc = ttk.LabelFrame(scrollable_frame, text="Removable Drives & Diagnostics", padding=(10, 8))
        sec_misc.pack(fill="x", expand=True, pady=6)

        ttk.Button(sec_misc, text="Reset Remembered Drive Rules", command=self._clear_remembered_drives).pack(anchor="w", pady=3)
        ttk.Button(sec_misc, text="Open Diagnostics Log Folder", command=self._open_logs_folder).pack(anchor="w", pady=3)

        # Bottom action bar
        save_frame = ttk.Frame(scrollable_frame, padding=(0, 10))
        save_frame.pack(fill="x")
        ttk.Button(save_frame, text="Save Settings", command=self.save_values, width=18).pack(side="left")

    def load_values(self) -> None:
        cfg = self.config_manager.config
        self.bin_dir_var.set(cfg.clamav_bin_dir)
        self.clamd_host_var.set(cfg.clamd_host)
        self.clamd_port_var.set(cfg.clamd_port)
        self.prefer_clamd_var.set(cfg.prefer_clamd)
        self.quar_dir_var.set(cfg.quarantine_dir)
        self.auto_upd_var.set(cfg.auto_update_enabled)
        self.interval_var.set(cfg.update_interval_hours)
        self.rt_enabled_var.set(cfg.realtime_watch_enabled)
        self.rt_auto_quar_var.set(cfg.realtime_auto_quarantine)

        # Populate watched directories listbox
        self.watched_listbox.delete(0, "end")
        for d in cfg.watched_directories:
            self.watched_listbox.insert("end", d)

        self.startup_var.set(is_startup_registered())
        self._check_shell_status()

    def _add_downloads_dir(self) -> None:
        user_home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        dl = os.path.join(user_home, "Downloads")
        if not os.path.isdir(dl):
            messagebox.showwarning("TinyAV", f"Downloads folder not found at: {dl}")
            return
        current = list(self.watched_listbox.get(0, "end"))
        if dl not in current:
            self.watched_listbox.insert("end", dl)
        else:
            messagebox.showinfo("TinyAV", "Downloads folder is already in the watch list.")

    def _add_custom_watched_dir(self) -> None:
        d = filedialog.askdirectory(title="Select Folder for Real-Time Monitoring")
        if d:
            norm = os.path.normpath(d)
            current = list(self.watched_listbox.get(0, "end"))
            if norm not in current:
                self.watched_listbox.insert("end", norm)
            else:
                messagebox.showinfo("TinyAV", "Folder is already in the watch list.")

    def _remove_watched_dir(self) -> None:
        sel = self.watched_listbox.curselection()
        if not sel:
            messagebox.showinfo("TinyAV", "Please select a directory to remove.")
            return
        self.watched_listbox.delete(sel[0])

    def _check_shell_status(self) -> None:
        reg = is_context_menu_registered()
        if reg:
            self.shell_status_lbl.config(text="Registered (Enabled)", foreground="#28a745")
        else:
            self.shell_status_lbl.config(text="Not Registered", foreground="#dc3545")

    def _browse_bin_dir(self) -> None:
        d = filedialog.askdirectory(title="Select ClamAV bin directory")
        if d:
            self.bin_dir_var.set(d)

    def _auto_detect_bin(self) -> None:
        found = self.engine.find_binary("clamscan")
        if found:
            detected_dir = os.path.dirname(found)
            self.bin_dir_var.set(detected_dir)
            messagebox.showinfo("ClamAV Found", f"Detected ClamAV binaries at:\n{detected_dir}")
        else:
            messagebox.showwarning("Not Found", "Could not locate clamscan.exe in standard directories or PATH.")

    def _generate_configs(self) -> None:
        target_dir = self.bin_dir_var.get().strip()
        from app.core.config_generator import ClamAVConfigGenerator
        success, msg, files = ClamAVConfigGenerator.generate_configs(
            clamav_dir=target_dir,
            config_manager=self.config_manager,
            engine=self.engine,
        )
        if success:
            detected = ClamAVConfigGenerator.detect_clamav_dir(self.config_manager, self.engine)
            if detected:
                self.bin_dir_var.set(detected)
            messagebox.showinfo("Configuration Generated", msg)
            self.on_settings_saved()
        else:
            messagebox.showerror("Configuration Error", msg)

    def _test_clamd(self) -> None:
        host = self.clamd_host_var.get().strip()
        try:
            port = int(self.clamd_port_var.get())
        except (tk.TclError, ValueError):
            messagebox.showerror("Invalid Port", "Please enter a valid numeric port for clamd (e.g. 3310).")
            return

        try:
            client = clamd.ClamdNetworkSocket(host=host, port=port, timeout=2.0)
            if client.ping() == "PONG":
                ver = client.version()
                messagebox.showinfo("Success", f"Connected to clamd successfully!\nVersion: {ver}")
            else:
                messagebox.showerror("Error", "clamd did not respond with PONG.")
        except Exception as exc:
            messagebox.showerror("Connection Failed", f"Could not connect to clamd at {host}:{port}:\n{exc}")

    def _browse_quar_dir(self) -> None:
        d = filedialog.askdirectory(title="Select Quarantine Directory")
        if d:
            self.quar_dir_var.set(d)

    def _register_shell(self) -> None:
        ok, msg = register_context_menu_elevated()
        if ok:
            messagebox.showinfo("TinyAV", msg)
        else:
            messagebox.showerror("TinyAV", msg)
        self._check_shell_status()
        self.after(1000, self._check_shell_status)
        self.after(2500, self._check_shell_status)

    def _unregister_shell(self) -> None:
        ok, msg = unregister_context_menu_elevated()
        if ok:
            messagebox.showinfo("TinyAV", msg)
        else:
            messagebox.showerror("TinyAV", msg)
        self._check_shell_status()
        self.after(1000, self._check_shell_status)
        self.after(2500, self._check_shell_status)

    def _on_startup_toggle(self) -> None:
        if self.startup_var.get():
            ok, msg = enable_startup()
            if ok:
                messagebox.showinfo(
                    "Auto-Start Enabled",
                    "TinyAV is configured to start automatically at Windows login.\nIt runs silently in your system tray with zero console windows.",
                )
            else:
                self.startup_var.set(False)
                messagebox.showerror("Auto-Start Error", f"Failed to enable auto-start:\n{msg}")
        else:
            disable_startup()
            messagebox.showinfo(
                "Auto-Start Disabled",
                "TinyAV will no longer start automatically at Windows login.",
            )

    def _clear_remembered_drives(self) -> None:
        self.config_manager.update(remembered_drives={})
        messagebox.showinfo("TinyAV", "Cleared all remembered USB drive preferences.")

    def _open_logs_folder(self) -> None:
        log_dir = get_default_log_dir()
        if os.path.exists(log_dir):
            subprocess.Popen(f'explorer "{log_dir}"')

    def save_values(self) -> None:
        bin_dir = self.bin_dir_var.get().strip()
        quar_dir = self.quar_dir_var.get().strip()
        watched_dirs = list(self.watched_listbox.get(0, "end"))

        try:
            port = int(self.clamd_port_var.get())
        except (tk.TclError, ValueError):
            messagebox.showerror("Invalid Port", "Please enter a valid numeric port for clamd (e.g. 3310).")
            return

        try:
            interval = max(1, int(self.interval_var.get()))
        except (tk.TclError, ValueError):
            messagebox.showerror("Invalid Interval", "Please enter a valid numeric interval in hours (1-48).")
            return

        if quar_dir:
            os.makedirs(quar_dir, exist_ok=True)

        self.config_manager.update(
            clamav_bin_dir=bin_dir,
            clamd_host=self.clamd_host_var.get().strip(),
            clamd_port=port,
            prefer_clamd=self.prefer_clamd_var.get(),
            quarantine_dir=quar_dir,
            auto_update_enabled=self.auto_upd_var.get(),
            update_interval_hours=interval,
            realtime_watch_enabled=self.rt_enabled_var.get(),
            watched_directories=watched_dirs,
            realtime_auto_quarantine=self.rt_auto_quar_var.get(),
        )

        self.update_manager.reschedule(
            interval_hours=self.config_manager.config.update_interval_hours,
            enabled=self.config_manager.config.auto_update_enabled,
        )

        self.engine.refresh_engine()
        self.on_settings_saved()
        messagebox.showinfo("TinyAV", "Settings saved successfully.")
