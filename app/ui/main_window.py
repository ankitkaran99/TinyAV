import os
import queue
import time
import tkinter as tk
from tkinter import ttk
from typing import Optional

from app.core.binary_updater import ClamAVBinaryUpdater
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.folder_watcher import RealtimeFolderWatcher
from app.core.logger import get_logger
from app.core.quarantine import QuarantineManager
from app.core.updater import UpdateManager
from app.platform_win.drive_watcher import DriveWatcher
from app.platform_win.win_drives import DriveInfo
from app.ui.quick_scan_dialog import UsbPromptDialog
from app.ui.tabs.quarantine_tab import QuarantineTab
from app.ui.tabs.scan_tab import ScanTab
from app.ui.tabs.settings_tab import SettingsTab
from app.ui.tabs.update_tab import UpdateTab
from app.ui.threat_dialog import ThreatNotificationDialog
from app.ui.tray import TrayManager
from app.ui.watched_progress_overlay import WatchedProgressOverlay

logger = get_logger()

class MainWindow:
    def __init__(
        self,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        update_manager: UpdateManager,
        start_minimized: bool = False,
    ):
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.update_manager = update_manager
        self.binary_updater = ClamAVBinaryUpdater(self.config_manager, self.engine)

        self.root = tk.Tk()
        self.root.title("TinyAV - ClamAV Windows Companion")
        self.root.geometry("820x620")
        self.root.minsize(720, 520)

        # Style setup
        self.style = ttk.Style(self.root)
        try:
            self.style.theme_use("vista")
        except Exception:
            pass

        self.ui_queue: queue.Queue = queue.Queue()
        self.drive_watcher: Optional[DriveWatcher] = None
        self._watchdog_counter = 0
        self._last_clean_notify_time = 0.0
        self._notified_minimized = False

        self._build_ui()

        # System tray setup
        self.tray = TrayManager(
            on_show=lambda: self.ui_queue.put(("TRAY_ACTION", "show")),
            on_scan_processes=lambda: self.ui_queue.put(("TRAY_ACTION", "scan_processes")),
            on_update=lambda: self.ui_queue.put(("TRAY_ACTION", "update")),
            on_settings=lambda: self.ui_queue.put(("TRAY_ACTION", "settings")),
            on_exit=lambda: self.ui_queue.put(("TRAY_ACTION", "exit")),
        )
        self.tray.start()

        # Update manager status hooks for tray notifications
        self.update_manager.on_update_status_change = self._on_updater_status_change

        # Setup Removable Drive Watcher
        self.drive_watcher = DriveWatcher(callback=self._on_usb_drive_detected)
        self.drive_watcher.start()

        # Desktop bottom-right floating progress overlay
        self.watched_progress_overlay = WatchedProgressOverlay(self.root)

        # Setup Real-time Directory Watcher (e.g. Downloads folder)
        self.folder_watcher = RealtimeFolderWatcher(
            config_manager=self.config_manager,
            engine=self.engine,
            quarantine_manager=self.quarantine_manager,
            on_threat_detected=lambda path, threat, quar: self.ui_queue.put(("REALTIME_THREAT", (path, threat, quar))),
            on_scan_clean=lambda path: self.ui_queue.put(("REALTIME_CLEAN", path)),
            on_scan_start=lambda path: self.ui_queue.put(("REALTIME_START", path)),
            on_batch_clean=lambda count, sample: self.ui_queue.put(("REALTIME_BATCH_CLEAN", (count, sample))),
            on_queue_progress=lambda done, total, path: self.ui_queue.put(("REALTIME_PROGRESS", (done, total, path))),
            on_queue_complete=lambda total, threats: self.ui_queue.put(("REALTIME_COMPLETE", (total, threats))),
        )
        self.folder_watcher.start()

        # Start background update scheduler
        self.update_manager.start_scheduler()

        # Window protocol: close button minimizes to tray
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        # Queue polling
        self.root.after(100, self._process_queue)

        if start_minimized:
            self.hide_to_tray()
        else:
            self.root.after(600, self._check_first_run_setup)

    def _check_first_run_setup(self) -> None:
        from app.core.auto_setup import AutoProvisioner
        if AutoProvisioner.is_setup_needed(self.engine):
            from app.ui.setup_dialog import FirstRunSetupDialog
            def _on_done():
                try:
                    self.engine.refresh_engine()
                    if hasattr(self, "update_tab"):
                        self.update_tab.refresh_info()
                    if hasattr(self, "settings_tab"):
                        self.settings_tab.load_values()
                    if hasattr(self, "quarantine_tab"):
                        self.quarantine_tab.refresh_items()
                    self._set_app_state("idle")
                except Exception as exc:
                    logger.error(f"Error in setup on_done: {exc}", exc_info=True)

            FirstRunSetupDialog(
                parent=self.root,
                config_manager=self.config_manager,
                engine=self.engine,
                on_completed=_on_done,
            )

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        # Tabs
        self.scan_tab = ScanTab(
            parent=self.notebook,
            config_manager=self.config_manager,
            engine=self.engine,
            quarantine_manager=self.quarantine_manager,
            ui_queue=self.ui_queue,
            on_scan_state_change=self._set_app_state,
        )
        self.quarantine_tab = QuarantineTab(
            parent=self.notebook,
            quarantine_manager=self.quarantine_manager,
        )
        self.update_tab = UpdateTab(
            parent=self.notebook,
            config_manager=self.config_manager,
            engine=self.engine,
            update_manager=self.update_manager,
            binary_updater=self.binary_updater,
            ui_queue=self.ui_queue,
            on_update_state_change=self._set_app_state,
        )
        self.settings_tab = SettingsTab(
            parent=self.notebook,
            config_manager=self.config_manager,
            engine=self.engine,
            update_manager=self.update_manager,
            on_settings_saved=self._on_settings_saved,
        )

        self.notebook.add(self.scan_tab, text="  Scanner  ")
        self.notebook.add(self.quarantine_tab, text="  Quarantine Vault  ")
        self.notebook.add(self.update_tab, text="  Updates & Signatures  ")
        self.notebook.add(self.settings_tab, text="  Settings  ")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        # Footer status bar with bottom-right watched folder queue progress bar
        self.footer_frame = ttk.Frame(self.root, padding=(10, 4))
        self.footer_frame.grid(row=1, column=0, sticky="ew")
        self.footer_frame.columnconfigure(0, weight=1)

        self.footer_engine_label = ttk.Label(
            self.footer_frame,
            text=f"Engine: {self.engine.engine_version}",
            font=("Segoe UI", 8),
            foreground="#666666",
        )
        self.footer_engine_label.grid(row=0, column=0, sticky="w")

        self.footer_right_frame = ttk.Frame(self.footer_frame)
        self.footer_right_frame.grid(row=0, column=1, sticky="e")

        self.footer_queue_label = ttk.Label(
            self.footer_right_frame,
            text="",
            font=("Segoe UI", 8),
            foreground="#555555",
        )
        self.footer_queue_label.pack(side="left", padx=(0, 6))

        self.footer_progress_bar = ttk.Progressbar(
            self.footer_right_frame,
            orient="horizontal",
            mode="determinate",
            length=140,
        )

    def _on_tab_changed(self, event=None) -> None:
        try:
            selected = self.notebook.select()
            if selected == str(self.quarantine_tab):
                self.quarantine_tab.refresh_items()
            elif selected == str(self.update_tab):
                self.update_tab.refresh_info()
        except Exception as exc:
            logger.debug(f"Error handling tab switch: {exc}")

    def _set_app_state(self, state: str) -> None:
        """Update tray icon according to app state: 'idle' | 'scanning' | 'updating' | 'threat'."""
        self.tray.set_state(state)

    def _check_overall_threat_state(self) -> None:
        """Restores tray icon to green ('idle') if no active/unresolved threats remain in ScanTab."""
        if hasattr(self, "scan_tab"):
            self.scan_tab._check_and_update_threat_state()
        else:
            self._set_app_state("idle")

    def _on_updater_status_change(self, status: str, is_updating: bool, err_msg: Optional[str]) -> None:
        if err_msg:
            self.tray.notify("Definition Update Failed", err_msg)
        elif not is_updating:
            self.tray.set_state("idle")

    def _on_usb_drive_detected(self, drive_info: DriveInfo) -> None:
        self.ui_queue.put(("USB_ATTACHED", drive_info))

    def _on_settings_saved(self) -> None:
        self.quarantine_manager.quarantine_dir = self.config_manager.config.quarantine_dir
        self.update_tab.refresh_info()
        self.quarantine_tab.refresh_items()
        self.folder_watcher.restart()

    def hide_to_tray(self) -> None:
        self.root.withdraw()
        if not self._notified_minimized:
            self._notified_minimized = True
            self.tray.notify("TinyAV", "TinyAV is running in the background. Access it via the system tray.")

    def show_window(self) -> None:
        logger.info("Restoring TinyAV main window from system tray...")
        try:
            # 1. Restore Tkinter window state
            self.root.deiconify()
            self.root.state("normal")

            # 2. Force window over other active applications
            self.root.attributes("-topmost", True)
            self.root.update_idletasks()
            self.root.attributes("-topmost", False)
            self.root.lift()
            self.root.focus_force()

            # 3. Explicit Win32 OS-level window restoration
            if os.name == "nt":
                try:
                    import ctypes
                    user32 = ctypes.windll.user32
                    wid = self.root.winfo_id()
                    hwnd = user32.GetParent(wid) or wid
                    user32.ShowWindow(hwnd, 9)  # SW_RESTORE = 9
                    user32.SetForegroundWindow(hwnd)
                except Exception as w32_err:
                    logger.debug(f"Win32 ShowWindow restore fallback: {w32_err}")

            try:
                self.quarantine_tab.refresh_items()
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"Error in show_window: {exc}", exc_info=True)

    def _handle_single_ui_event(self, event_type: str, data: any) -> None:
        if event_type.startswith("SCAN_"):
            self.scan_tab.handle_ui_event(event_type, data)
        elif event_type.startswith("UPDATE_") or event_type.startswith("BINARY_"):
            self.update_tab.handle_ui_event(event_type, data)
        elif event_type == "QUARANTINE_UPDATED":
            self.quarantine_tab.refresh_items()
        elif event_type == "REALTIME_START":
            path = data
            fname = os.path.basename(path)
            logger.info(f"Auto-scanning new download: {fname}")
            if hasattr(self, "scan_tab") and not self.scan_tab.is_scanning:
                self.scan_tab.status_label.config(
                    text=f"Auto-scanning download: {fname}..."
                )
        elif event_type == "REALTIME_THREAT":
            path, threat, auto_quar = data
            self._set_app_state("threat")
            fname = os.path.basename(path)
            if auto_quar:
                msg = f"Infected file '{fname}' ({threat}) was automatically neutralized and moved to Quarantine."
                self.tray.notify("Threat Auto-Quarantined", msg)
                self.quarantine_tab.refresh_items()
                if hasattr(self, "scan_tab") and not self.scan_tab.is_scanning:
                    self.scan_tab.status_label.config(
                        text=f"Threat auto-quarantined: {fname} ({threat})"
                    )

                # Show prominent desktop threat alert dialog
                try:
                    ThreatNotificationDialog(
                        file_path=path,
                        threat_name=threat,
                        auto_quarantined=True,
                        on_action=lambda: (
                            self.show_window(),
                            self.notebook.select(1),
                            self.quarantine_tab.refresh_items(),
                            self._check_overall_threat_state(),
                        ),
                        on_dismiss=self._check_overall_threat_state,
                    )
                except Exception as diag_err:
                    logger.debug(f"Could not open ThreatNotificationDialog: {diag_err}")
            else:
                msg = f"Infected file detected: '{fname}' ({threat})!"
                self.tray.notify("Real-Time Threat Detected", msg)
                self.show_window()
                self.notebook.select(0)
                self.scan_tab.tree.insert("", "end", values=(path, threat, "Detected (Realtime)"))
                if hasattr(self, "scan_tab") and not self.scan_tab.is_scanning:
                    self.scan_tab.status_label.config(
                        text=f"Real-time threat detected: {fname} ({threat})!"
                    )

                # Show prominent desktop threat alert dialog
                try:
                    ThreatNotificationDialog(
                        file_path=path,
                        threat_name=threat,
                        auto_quarantined=False,
                        on_action=lambda: (
                            self.show_window(),
                            self.notebook.select(0),
                        ),
                        on_dismiss=self._check_overall_threat_state,
                    )
                except Exception as diag_err:
                    logger.debug(f"Could not open ThreatNotificationDialog: {diag_err}")
        elif event_type == "REALTIME_CLEAN":
            path = data
            fname = os.path.basename(path)
            logger.info(f"Verified clean: {fname}")
            if hasattr(self, "scan_tab") and not self.scan_tab.is_scanning:
                self.scan_tab.status_label.config(
                    text=f"Auto-scan clean: {fname}"
                )
            if self.config_manager.config.notify_on_clean:
                now = time.time()
                if now - self._last_clean_notify_time >= 3.0:
                    self._last_clean_notify_time = now
                    self.tray.notify(
                        "Download Verified Safe",
                        f"'{fname}' was scanned and verified clean.",
                    )
        elif event_type == "REALTIME_BATCH_CLEAN":
            count, sample = data
            logger.info(f"Verified clean batch: {count} files (e.g. {sample})")
            if hasattr(self, "scan_tab") and not self.scan_tab.is_scanning:
                self.scan_tab.status_label.config(
                    text=f"Auto-scan clean: {count} files verified safe"
                )
            if self.config_manager.config.notify_on_clean:
                now = time.time()
                if now - self._last_clean_notify_time >= 3.0:
                    self._last_clean_notify_time = now
                    self.tray.notify(
                        "Files Verified Safe",
                        f"{count} extracted/downloaded files were scanned and verified clean.",
                    )
        elif event_type == "REALTIME_PROGRESS":
            done, total, path = data
            fname = os.path.basename(path) if path else ""
            pct = int((done / total) * 100) if total > 0 else 0

            # 1. Update floating desktop bottom-right corner overlay
            if hasattr(self, "watched_progress_overlay") and self.watched_progress_overlay:
                self.watched_progress_overlay.update_progress(done, total, path)

            # 2. Update MainWindow bottom-right status
            if hasattr(self, "footer_progress_bar"):
                if not self.footer_progress_bar.winfo_ismapped():
                    self.footer_progress_bar.pack(side="right")
                self.footer_progress_bar.config(value=pct)
            if hasattr(self, "footer_queue_label"):
                status_txt = f"Watched scan: {done}/{total}"
                if fname:
                    display_name = fname[:18] + "..." if len(fname) > 18 else fname
                    status_txt += f" ({display_name})"
                self.footer_queue_label.config(text=status_txt)

            # 3. Update tray state
            self._set_app_state("scanning")

        elif event_type == "REALTIME_COMPLETE":
            total, threats = data
            # 1. Update floating desktop overlay
            if hasattr(self, "watched_progress_overlay") and self.watched_progress_overlay:
                self.watched_progress_overlay.on_completed(total, threats)

            # 2. Update MainWindow bottom-right status
            if hasattr(self, "footer_progress_bar"):
                self.footer_progress_bar.config(value=100)
            if hasattr(self, "footer_queue_label"):
                if threats > 0:
                    self.footer_queue_label.config(text=f"Watched scan: {threats} threat(s) detected")
                else:
                    self.footer_queue_label.config(text=f"Watched scan: {total} files clean")

            self.root.after(3000, self._reset_footer_queue)

            # 3. Restore tray state
            self._check_overall_threat_state()
        elif event_type == "TRAY_ACTION":
            action = data
            logger.info(f"Processing TRAY_ACTION: {action}")
            if action == "show":
                self.show_window()
            elif action == "scan_processes":
                self.show_window()
                self.notebook.select(0)
                self.scan_tab.scope_var.set("processes")
                self.scan_tab._on_scope_changed()
                self.scan_tab.start_scan()
            elif action == "update":
                self.show_window()
                self.notebook.select(2)
                self.update_tab.trigger_manual_update()
            elif action == "settings":
                self.show_window()
                self.notebook.select(3)
            elif action == "exit":
                self.exit_app()
        elif event_type == "USB_ATTACHED":
            drive_info: DriveInfo = data

            # Check USB Autorun Immunization
            if self.config_manager.config.usb_autorun_immunize and drive_info.is_removable:
                try:
                    from app.platform_win.autorun_immunizer import immunize_drive
                    immunized, imm_msg = immunize_drive(drive_info.letter)
                    if immunized:
                        self.tray.notify(
                            "USB Drive Immunized",
                            f"Renamed autorun.inf to autorun.inf.tiny on {drive_info.letter} ({drive_info.label}).",
                        )
                except Exception as imm_err:
                    logger.debug(f"USB immunization error: {imm_err}")

            pref = self.config_manager.config.remembered_drives.get(drive_info.serial_number)
            if pref == "auto_scan":
                self.show_window()
                self.notebook.select(0)
                self.scan_tab.start_scan(preselected_path=drive_info.letter)
            elif pref == "ignore":
                pass
            else:
                UsbPromptDialog(
                    drive_info=drive_info,
                    config_manager=self.config_manager,
                    on_scan_drive=lambda letter: (
                        self.show_window(),
                        self.notebook.select(0),
                        self.scan_tab.start_scan(preselected_path=letter),
                    ),
                )

    def _process_queue(self) -> None:
        try:
            # Drain up to 60 events per tick
            for _ in range(60):
                try:
                    item = self.ui_queue.get_nowait()
                except queue.Empty:
                    break

                try:
                    event_type, data = item
                    self._handle_single_ui_event(event_type, data)
                except Exception as exc:
                    logger.error(f"Error handling UI event '{item}': {exc}", exc_info=True)

        except Exception as exc:
            logger.error(f"Unexpected error in _process_queue: {exc}", exc_info=True)
        finally:
            # System tray thread watchdog check every ~3-5 seconds (every 30 ticks)
            self._watchdog_counter += 1
            if self._watchdog_counter >= 30:
                self._watchdog_counter = 0
                if hasattr(self, "tray") and not self.tray.is_alive():
                    logger.warning("System tray thread is not alive. Automatically restarting tray...")
                    self.tray.restart()

            # ALWAYS reschedule next tick - ensures queue polling never dies
            try:
                if self.root.winfo_exists():
                    self.root.after(100, self._process_queue)
            except Exception:
                pass

    def _reset_footer_queue(self) -> None:
        try:
            if hasattr(self, "footer_queue_label"):
                self.footer_queue_label.config(text="")
            if hasattr(self, "footer_progress_bar"):
                self.footer_progress_bar.config(value=0)
                if self.footer_progress_bar.winfo_ismapped():
                    self.footer_progress_bar.pack_forget()
        except Exception:
            pass

    def exit_app(self) -> None:
        logger.info("Exiting TinyAV application...")
        if hasattr(self, "scan_tab") and self.scan_tab.is_scanning:
            self.scan_tab.cancel_scan()
        if hasattr(self, "engine"):
            self.engine.cancel_active_scan()
        if hasattr(self, "folder_watcher") and self.folder_watcher:
            self.folder_watcher.stop()
        if hasattr(self, "watched_progress_overlay") and self.watched_progress_overlay:
            try:
                self.watched_progress_overlay.destroy()
            except Exception:
                pass
        if self.drive_watcher:
            self.drive_watcher.stop()
        self.update_manager.stop_scheduler()
        self.tray.stop()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
