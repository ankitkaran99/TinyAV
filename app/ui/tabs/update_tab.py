import os
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk
from typing import Callable, Optional

from app.core.binary_updater import ClamAVBinaryUpdater, ClamAVReleaseInfo
from app.core.config import ConfigManager
from app.core.config_generator import ClamAVConfigGenerator
from app.core.engine import ClamAVEngine, EngineMode
from app.core.updater import UpdateManager


class UpdateTab(ttk.Frame):
    def __init__(
        self,
        parent: ttk.Notebook,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        update_manager: UpdateManager,
        binary_updater: ClamAVBinaryUpdater,
        ui_queue: queue.Queue,
        on_update_state_change: Callable[[str], None],
    ):
        super().__init__(parent)
        self.config_manager = config_manager
        self.engine = engine
        self.update_manager = update_manager
        self.binary_updater = binary_updater
        self.ui_queue = ui_queue
        self.on_update_state_change = on_update_state_change

        self.latest_release_info: Optional[ClamAVReleaseInfo] = None

        self._build_ui()
        self.refresh_info()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

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

        # 1. Engine & Definition Overview Frame
        info_frame = ttk.LabelFrame(scrollable_frame, text="ClamAV Engine & Signatures Status", padding=(12, 10))
        info_frame.pack(fill="x", expand=True, pady=(0, 6))
        info_frame.columnconfigure(1, weight=1)

        # Mode
        ttk.Label(info_frame, text="Active Engine Mode:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=3)
        self.mode_val_lbl = ttk.Label(info_frame, text="Detecting...")
        self.mode_val_lbl.grid(row=0, column=1, sticky="w", pady=3, padx=8)

        # Engine Version
        ttk.Label(info_frame, text="Engine Version:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=3)
        self.eng_ver_lbl = ttk.Label(info_frame, text="Unknown")
        self.eng_ver_lbl.grid(row=1, column=1, sticky="w", pady=3, padx=8)

        # Definition Version
        ttk.Label(info_frame, text="Definition Signatures:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=3)
        self.def_ver_lbl = ttk.Label(info_frame, text="Unknown")
        self.def_ver_lbl.grid(row=2, column=1, sticky="w", pady=3, padx=8)

        # Last Updated
        ttk.Label(info_frame, text="Last Checked/Updated:", font=("Segoe UI", 9, "bold")).grid(row=3, column=0, sticky="w", pady=3)
        self.last_upd_lbl = ttk.Label(info_frame, text="Never")
        self.last_upd_lbl.grid(row=3, column=1, sticky="w", pady=3, padx=8)

        # Schedule
        ttk.Label(info_frame, text="Schedule:", font=("Segoe UI", 9, "bold")).grid(row=4, column=0, sticky="w", pady=3)
        self.sched_lbl = ttk.Label(info_frame, text="Every 4 hours")
        self.sched_lbl.grid(row=4, column=1, sticky="w", pady=3, padx=8)

        # 2. Virus Definitions Updates (freshclam)
        act_frame = ttk.LabelFrame(scrollable_frame, text="Virus Signatures Updates (freshclam)", padding=(12, 8))
        act_frame.pack(fill="x", expand=True, pady=6)
        act_frame.columnconfigure(2, weight=1)

        # Manual Update & Conf Gen Buttons
        top_act_box = ttk.Frame(act_frame)
        top_act_box.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self.update_btn = ttk.Button(top_act_box, text="Update Definitions Now", command=self.trigger_manual_update, width=24)
        self.update_btn.pack(side="left")

        self.gen_conf_btn = ttk.Button(top_act_box, text="Auto-Generate Conf Files", command=self._generate_configs)
        self.gen_conf_btn.pack(side="left", padx=8)

        self.prog_spinner = ttk.Progressbar(top_act_box, mode="indeterminate", length=140)

        # Interval Configuration Row
        sched_row = ttk.Frame(act_frame)
        sched_row.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(2, 0))

        self.tab_auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(sched_row, text="Enable periodic updates", variable=self.tab_auto_var).pack(side="left", padx=(0, 10))

        ttk.Label(sched_row, text="Interval:").pack(side="left", padx=(0, 4))
        self.interval_combo_var = tk.StringVar(value="4 hours")
        self.interval_combo = ttk.Combobox(
            sched_row,
            textvariable=self.interval_combo_var,
            values=["1 hour", "2 hours", "4 hours", "6 hours", "8 hours", "12 hours", "24 hours"],
            state="readonly",
            width=10,
        )
        self.interval_combo.pack(side="left", padx=4)

        ttk.Button(sched_row, text="Apply Schedule", command=self._apply_schedule).pack(side="left", padx=10)

        # 3. ClamAV Engine Binary Updates (GitHub Releases)
        bin_frame = ttk.LabelFrame(scrollable_frame, text="ClamAV Engine Binary Updates (Cisco-Talos/clamav)", padding=(12, 8))
        bin_frame.pack(fill="x", expand=True, pady=6)
        bin_frame.columnconfigure(1, weight=1)

        # Row 0: Installed Binaries
        ttk.Label(bin_frame, text="Installed Engine Binaries:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=3)
        self.bin_installed_lbl = ttk.Label(bin_frame, text="Detecting...")
        self.bin_installed_lbl.grid(row=0, column=1, sticky="w", pady=3, padx=8)

        # Row 1: Latest GitHub Release
        ttk.Label(bin_frame, text="Latest GitHub Release:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=3)
        gh_status_box = ttk.Frame(bin_frame)
        gh_status_box.grid(row=1, column=1, sticky="w", pady=3, padx=8)

        self.bin_latest_lbl = ttk.Label(gh_status_box, text="Not checked")
        self.bin_latest_lbl.pack(side="left")

        self.bin_badge_lbl = ttk.Label(gh_status_box, text="", font=("Segoe UI", 9, "bold"))
        self.bin_badge_lbl.pack(side="left", padx=10)

        # Row 2: Action Buttons
        bin_btn_box = ttk.Frame(bin_frame)
        bin_btn_box.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 4))

        self.check_bin_btn = ttk.Button(bin_btn_box, text="Check for Engine Updates", command=self._check_engine_updates)
        self.check_bin_btn.pack(side="left", padx=(0, 6))

        self.apply_zip_btn = ttk.Button(
            bin_btn_box,
            text="Update Engine (Portable ZIP)",
            command=self._apply_portable_zip,
            state="disabled",
        )
        self.apply_zip_btn.pack(side="left", padx=6)

        self.dl_msi_btn = ttk.Button(
            bin_btn_box,
            text="Download Installer (MSI)",
            command=self._download_msi,
            state="disabled",
        )
        self.dl_msi_btn.pack(side="left", padx=6)

        self.view_gh_btn = ttk.Button(bin_btn_box, text="View on GitHub", command=self._open_github_releases)
        self.view_gh_btn.pack(side="left", padx=6)

        # Row 3: Progress & Status
        self.bin_prog_box = ttk.Frame(bin_frame)
        self.bin_prog_box.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        self.bin_prog_box.columnconfigure(0, weight=1)

        self.bin_prog_bar = ttk.Progressbar(self.bin_prog_box, mode="determinate")
        self.bin_status_lbl = ttk.Label(self.bin_prog_box, text="", foreground="#555555")

        # 4. Activity Output Box
        log_frame = ttk.LabelFrame(scrollable_frame, text="Update Activity Output", padding=(10, 8))
        log_frame.pack(fill="both", expand=True, pady=(6, 4))
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap="word", height=9, font=("Consolas", 9), state="disabled")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    def _apply_schedule(self) -> None:
        raw_val = self.interval_combo_var.get()
        hours = 4
        try:
            hours = int(raw_val.split()[0])
        except Exception:
            hours = 4

        enabled = self.tab_auto_var.get()
        self.config_manager.update(
            update_interval_hours=hours,
            auto_update_enabled=enabled,
        )
        self.update_manager.reschedule(interval_hours=hours, enabled=enabled)
        self.refresh_info()
        self.log_message(f"Schedule updated: {'Every ' + str(hours) + ' hours' if enabled else 'Disabled'}")

    def refresh_info(self) -> None:
        self.engine.refresh_engine()
        mode_text = {
            EngineMode.CLAMD: "clamd Daemon (High-Speed Local Socket)",
            EngineMode.CLAMSCAN: "clamscan CLI Executable",
            EngineMode.UNAVAILABLE: "Engine Not Found / Offline",
        }.get(self.engine.mode, "Unknown")
        self.mode_val_lbl.config(text=mode_text)

        self.eng_ver_lbl.config(text=self.engine.engine_version)
        self.def_ver_lbl.config(text=self.config_manager.config.definition_version)
        self.last_upd_lbl.config(text=self.config_manager.config.last_update_time or "Never")

        cfg = self.config_manager.config
        self.tab_auto_var.set(cfg.auto_update_enabled)
        self.interval_combo_var.set(f"{cfg.update_interval_hours} hours" if cfg.update_interval_hours != 1 else "1 hour")

        if cfg.auto_update_enabled:
            self.sched_lbl.config(text=f"Every {cfg.update_interval_hours} hours (Active)")
        else:
            self.sched_lbl.config(text="Disabled (Manual only)")

        # Update installed binary info
        inst_dir = cfg.clamav_bin_dir or ClamAVConfigGenerator.detect_clamav_dir(self.config_manager, self.engine) or "Unset"
        self.bin_installed_lbl.config(text=f"{self.engine.engine_version} (at: {inst_dir})")

    def log_message(self, message: str) -> None:
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _generate_configs(self) -> None:
        self.log_message("Auto-generating optimized ClamAV configuration files...")
        success, msg, files = ClamAVConfigGenerator.generate_configs(
            config_manager=self.config_manager,
            engine=self.engine,
        )
        self.log_message(msg)
        if success:
            self.refresh_info()
            messagebox.showinfo("Configuration Generated", msg)
        else:
            messagebox.showerror("Configuration Error", msg)

    def trigger_manual_update(self) -> None:
        if self.update_manager.is_updating:
            return

        self.update_btn.config(state="disabled")
        self.prog_spinner.pack(side="left", padx=12)
        self.prog_spinner.start(10)
        self.log_message("Starting virus definition update via freshclam...")
        self.on_update_state_change("updating")

        def callback(success: bool, msg: str):
            self.ui_queue.put(("UPDATE_COMPLETED", (success, msg)))

        self.update_manager.run_update_async(is_scheduled=False, callback=callback)

    # --- ClamAV Engine Binary Updates Handlers ---

    def _check_engine_updates(self) -> None:
        if self.binary_updater.is_busy:
            return

        self.check_bin_btn.config(state="disabled")
        self.bin_latest_lbl.config(text="Checking GitHub API...")
        self.bin_badge_lbl.config(text="")
        self.log_message("Checking Cisco-Talos/clamav GitHub releases for latest ClamAV engine...")

        def worker():
            success, msg, info = self.binary_updater.check_for_updates()
            self.ui_queue.put(("BINARY_CHECK_RESULT", (success, msg, info)))

        threading.Thread(target=worker, daemon=True, name="ClamAV-ReleaseChecker").start()

    def _apply_portable_zip(self) -> None:
        if not self.latest_release_info or not self.latest_release_info.zip_asset:
            messagebox.showwarning("TinyAV", "No portable ZIP asset available for this system architecture.")
            return

        target_dir = self.config_manager.config.clamav_bin_dir
        if not target_dir:
            target_dir = ClamAVConfigGenerator.detect_clamav_dir(self.config_manager, self.engine) or r"C:\tools\clamav"

        asset = self.latest_release_info.zip_asset
        mb = asset.size / (1024 * 1024)
        confirm = messagebox.askyesno(
            "Update ClamAV Binaries",
            f"Download and install ClamAV {self.latest_release_info.version} portable binaries ({mb:.1f} MB)?\n\n"
            f"Destination: {target_dir}\n\n"
            f"Your existing configuration files and virus signatures will be preserved.",
        )
        if not confirm:
            return

        self._set_binary_busy(True)
        self.log_message(f"Starting portable ZIP update from: {asset.download_url}")

        def progress_cb(msg: str, pct: float):
            self.ui_queue.put(("BINARY_PROGRESS", (msg, pct)))

        def completion_cb(success: bool, msg: str):
            self.ui_queue.put(("BINARY_FINISHED", (success, msg)))

        self.binary_updater.update_portable_binaries_async(
            asset=asset,
            target_dir=target_dir,
            progress_callback=progress_cb,
            completion_callback=completion_cb,
        )

    def _download_msi(self) -> None:
        if not self.latest_release_info or not self.latest_release_info.msi_asset:
            messagebox.showwarning("TinyAV", "No Windows MSI installer available for this system architecture.")
            return

        asset = self.latest_release_info.msi_asset
        mb = asset.size / (1024 * 1024)
        confirm = messagebox.askyesno(
            "Download ClamAV Installer",
            f"Download ClamAV {self.latest_release_info.version} Windows Installer ({mb:.1f} MB) to your Downloads folder and run setup?",
        )
        if not confirm:
            return

        self._set_binary_busy(True)
        self.log_message(f"Starting MSI download from: {asset.download_url}")

        def progress_cb(msg: str, pct: float):
            self.ui_queue.put(("BINARY_PROGRESS", (msg, pct)))

        def completion_cb(success: bool, msg: str):
            self.ui_queue.put(("BINARY_FINISHED", (success, msg)))

        self.binary_updater.download_and_run_msi_async(
            asset=asset,
            progress_callback=progress_cb,
            completion_callback=completion_cb,
        )

    def _open_github_releases(self) -> None:
        url = self.latest_release_info.html_url if self.latest_release_info else "https://github.com/Cisco-Talos/clamav/releases"
        webbrowser.open(url)

    def _set_binary_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.check_bin_btn.config(state=state)
        self.apply_zip_btn.config(state=state if self.latest_release_info and self.latest_release_info.zip_asset else "disabled")
        self.dl_msi_btn.config(state=state if self.latest_release_info and self.latest_release_info.msi_asset else "disabled")

        if busy:
            self.bin_prog_bar.pack(fill="x", pady=2)
            self.bin_status_lbl.pack(anchor="w", pady=2)
            self.bin_prog_bar["value"] = 0
            self.on_update_state_change("updating")
        else:
            self.bin_prog_bar.pack_forget()
            self.bin_status_lbl.pack_forget()
            self.on_update_state_change("idle")

    def handle_ui_event(self, event_type: str, data: any) -> None:
        if event_type == "UPDATE_COMPLETED":
            success, msg = data
            self.prog_spinner.stop()
            self.prog_spinner.pack_forget()
            self.update_btn.config(state="normal")
            self.log_message(msg)
            self.refresh_info()
            self.on_update_state_change("idle")

        elif event_type == "BINARY_CHECK_RESULT":
            success, msg, info = data
            self.check_bin_btn.config(state="normal")
            self.log_message(msg)

            if success and info:
                self.latest_release_info = info
                self.bin_latest_lbl.config(text=f"v{info.version} ({info.tag_name})")

                if info.is_newer:
                    self.bin_badge_lbl.config(text=f"Update Available (Installed: v{info.current_version})", foreground="#d9534f")
                else:
                    self.bin_badge_lbl.config(text="Up to Date", foreground="#28a745")

                if info.zip_asset:
                    self.apply_zip_btn.config(state="normal")
                if info.msi_asset:
                    self.dl_msi_btn.config(state="normal")
            else:
                self.bin_latest_lbl.config(text="Check failed")
                self.bin_badge_lbl.config(text="", foreground="")
                messagebox.showwarning("ClamAV Release Check", msg)

        elif event_type == "BINARY_PROGRESS":
            msg, pct = data
            self.bin_prog_bar["value"] = pct
            self.bin_status_lbl.config(text=msg)

        elif event_type == "BINARY_FINISHED":
            success, msg = data
            self._set_binary_busy(False)
            self.log_message(msg)
            self.refresh_info()
            if success:
                messagebox.showinfo("ClamAV Engine Update", msg)
            else:
                messagebox.showerror("ClamAV Engine Update Failed", msg)
