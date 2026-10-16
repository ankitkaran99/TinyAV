import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, List, Optional

from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine, ScanDetection, ScanSummary
from app.core.logger import get_logger
from app.core.process_scanner import ProcessFileCollector
from app.core.quarantine import QuarantineManager
from app.platform_win.win_drives import DriveDetector

logger = get_logger()

class ScanTab(ttk.Frame):
    def __init__(
        self,
        parent: ttk.Notebook,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        ui_queue: queue.Queue,
        on_scan_state_change: Callable[[str], None],
    ):
        super().__init__(parent)
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.ui_queue = ui_queue
        self.on_scan_state_change = on_scan_state_change

        self.is_scanning = False
        self.cancel_event = threading.Event()
        self.current_scan_files: List[str] = []
        self.current_detections: List[ScanDetection] = []
        self.scan_start_time = 0.0
        self._timer_after_id: Optional[str] = None

        self._build_ui()
        self._refresh_drive_list()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # 1. Scope selection frame
        scope_frame = ttk.LabelFrame(self, text="Scan Scope & Target", padding=(10, 8))
        scope_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        scope_frame.columnconfigure(1, weight=1)

        self.scope_var = tk.StringVar(value="folder")

        r_files = ttk.Radiobutton(scope_frame, text="Files", value="files", variable=self.scope_var, command=self._on_scope_changed)
        r_folder = ttk.Radiobutton(scope_frame, text="Folder", value="folder", variable=self.scope_var, command=self._on_scope_changed)
        r_drive = ttk.Radiobutton(scope_frame, text="Drive", value="drive", variable=self.scope_var, command=self._on_scope_changed)
        r_proc = ttk.Radiobutton(scope_frame, text="Running Process Files", value="processes", variable=self.scope_var, command=self._on_scope_changed)

        r_files.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        r_folder.grid(row=0, column=1, padx=5, pady=2, sticky="w")
        r_drive.grid(row=0, column=2, padx=5, pady=2, sticky="w")
        r_proc.grid(row=0, column=3, padx=5, pady=2, sticky="w")

        # Target selection row
        self.target_subframe = ttk.Frame(scope_frame)
        self.target_subframe.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(6, 2))
        self.target_subframe.columnconfigure(1, weight=1)

        self.target_label = ttk.Label(self.target_subframe, text="Target:")
        self.target_label.grid(row=0, column=0, padx=(0, 5), sticky="w")

        self.target_var = tk.StringVar(value=os.path.expanduser("~"))
        self.target_entry = ttk.Entry(self.target_subframe, textvariable=self.target_var)
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=5)

        self.browse_btn = ttk.Button(self.target_subframe, text="Browse...", command=self._browse_target)
        self.browse_btn.grid(row=0, column=2, padx=5)

        # Drive combobox (hidden by default unless 'drive' is picked)
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(self.target_subframe, textvariable=self.drive_var, state="readonly", width=30)

        # 2. Controls & Progress Frame
        ctrl_frame = ttk.Frame(self, padding=(10, 5))
        ctrl_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        ctrl_frame.columnconfigure(0, weight=1)

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.grid(row=0, column=0, sticky="w", pady=(0, 5))

        self.start_btn = ttk.Button(btn_box, text="Start Scan", command=self.start_scan, width=14)
        self.start_btn.grid(row=0, column=0, padx=(0, 6))

        self.cancel_btn = ttk.Button(btn_box, text="Cancel Scan", command=self.cancel_scan, state="disabled", width=14)
        self.cancel_btn.grid(row=0, column=1, padx=6)

        self.progress_bar = ttk.Progressbar(ctrl_frame, orient="horizontal", mode="determinate")
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=2)

        self.status_label = ttk.Label(ctrl_frame, text="Ready to scan", anchor="w")
        self.status_label.grid(row=2, column=0, sticky="ew", pady=(2, 0))

        # 3. Summary Frame
        self.summary_frame = ttk.LabelFrame(self, text="Scan Summary", padding=(10, 6))
        self.summary_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        self.summary_frame.columnconfigure((0, 1, 2, 3), weight=1)

        self.scanned_lbl = ttk.Label(self.summary_frame, text="Scanned: 0", font=("Segoe UI", 9, "bold"))
        self.scanned_lbl.grid(row=0, column=0, sticky="w")

        self.threats_lbl = ttk.Label(self.summary_frame, text="Infected: 0", font=("Segoe UI", 9, "bold"), foreground="#28a745")
        self.threats_lbl.grid(row=0, column=1, sticky="w")

        self.errors_lbl = ttk.Label(self.summary_frame, text="Errors: 0", font=("Segoe UI", 9))
        self.errors_lbl.grid(row=0, column=2, sticky="w")

        self.time_lbl = ttk.Label(self.summary_frame, text="Duration: 0.0s", font=("Segoe UI", 9))
        self.time_lbl.grid(row=0, column=3, sticky="w")

        # 4. Results Treeview
        results_frame = ttk.LabelFrame(self, text="Detections", padding=(10, 8))
        results_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(5, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        columns = ("path", "threat", "action")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("path", text="File Path")
        self.tree.heading("threat", text="Threat Name")
        self.tree.heading("action", text="Action Taken")

        self.tree.column("path", width=420)
        self.tree.column("threat", width=180)
        self.tree.column("action", width=120)

        tree_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")

        # Actions for detections
        action_bar = ttk.Frame(results_frame, padding=(0, 6))
        action_bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.quarantine_btn = ttk.Button(action_bar, text="Quarantine Selected", command=self._quarantine_selected)
        self.quarantine_btn.pack(side="left", padx=(0, 4))

        self.quar_all_btn = ttk.Button(action_bar, text="Quarantine All", command=self._quarantine_all)
        self.quar_all_btn.pack(side="left", padx=4)

        self.delete_btn = ttk.Button(action_bar, text="Delete Selected", command=self._delete_selected)
        self.delete_btn.pack(side="left", padx=4)

        self.del_all_btn = ttk.Button(action_bar, text="Delete All", command=self._delete_all)
        self.del_all_btn.pack(side="left", padx=4)

        self.ignore_btn = ttk.Button(action_bar, text="Ignore Selected", command=self._ignore_selected)
        self.ignore_btn.pack(side="left", padx=4)

    def _refresh_drive_list(self) -> None:
        drives = DriveDetector.get_all_drives()
        options = ["All Fixed Drives"]
        for d in drives:
            d_type = "Removable" if d.is_removable else "Fixed"
            options.append(f"{d.letter} ({d.label or d_type})")
        self.drive_combo["values"] = options
        if options:
            self.drive_combo.current(0)

    def _on_scope_changed(self) -> None:
        scope = self.scope_var.get()
        self.target_subframe.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(6, 2))
        self.drive_combo.grid_forget()
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.browse_btn.grid(row=0, column=2, padx=5)

        if scope == "processes":
            self.target_subframe.grid_forget()
        elif scope == "drive":
            self.target_entry.grid_forget()
            self.browse_btn.grid_forget()
            self._refresh_drive_list()
            self.drive_combo.grid(row=0, column=1, sticky="ew", padx=5)
        elif scope in ("files", "folder"):
            self.target_entry.config(state="normal")
            self.browse_btn.config(state="normal")

    def _browse_target(self) -> None:
        scope = self.scope_var.get()
        if scope == "files":
            selected = filedialog.askopenfilenames(title="Select File(s) to Scan")
            if selected:
                self.target_var.set(";".join(selected))
        elif scope == "folder":
            selected = filedialog.askdirectory(title="Select Folder to Scan")
            if selected:
                self.target_var.set(selected)

    def start_scan(self, preselected_path: Optional[str] = None) -> None:
        if self.is_scanning:
            return

        if preselected_path:
            if os.path.isfile(preselected_path):
                self.scope_var.set("files")
                self.target_var.set(preselected_path)
            elif os.path.isdir(preselected_path):
                self.scope_var.set("folder")
                self.target_var.set(preselected_path)
            self._on_scope_changed()

        self.is_scanning = True
        self.cancel_event.clear()
        self.current_detections.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.start_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.status_label.config(text="Preparing file list...")
        self.progress_bar.config(mode="indeterminate")
        self.progress_bar.start(10)

        self.scanned_lbl.config(text="Scanned: 0")
        self.threats_lbl.config(text="Infected: 0", foreground="#28a745")
        self.errors_lbl.config(text="Errors: 0")
        self.time_lbl.config(text="Duration: 0.0s")

        self.on_scan_state_change("scanning")
        self.scan_start_time = time.time()
        self._schedule_duration_update()

        threading.Thread(
            target=self._scan_worker,
            daemon=True,
            name="TinyAV-ScanWorker",
        ).start()

    def _cancel_duration_timer(self) -> None:
        if self._timer_after_id:
            try:
                self.after_cancel(self._timer_after_id)
            except Exception:
                pass
            self._timer_after_id = None

    def _schedule_duration_update(self) -> None:
        self._cancel_duration_timer()
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return

        if not self.is_scanning or self.scan_start_time <= 0:
            return

        elapsed = max(0.0, time.time() - self.scan_start_time)
        if elapsed < 60:
            formatted = f"{elapsed:.1f}s"
        else:
            mins = int(elapsed // 60)
            secs = elapsed % 60
            formatted = f"{mins}m {secs:04.1f}s"

        try:
            self.time_lbl.config(text=f"Duration: {formatted}")
            self._timer_after_id = self.after(200, self._schedule_duration_update)
        except Exception:
            pass

    def cancel_scan(self) -> None:
        if self.is_scanning:
            self.cancel_event.set()
            self.engine.cancel_active_scan()
            self.status_label.config(text="Cancelling scan...")

    def _collect_files(self) -> List[str]:
        scope = self.scope_var.get()
        files_to_scan: List[str] = []

        if scope == "processes":
            files_to_scan, _ = ProcessFileCollector.collect_process_files()
            return files_to_scan

        quar_dir = (
            os.path.normcase(os.path.abspath(self.quarantine_manager.quarantine_dir))
            if self.quarantine_manager and self.quarantine_manager.quarantine_dir
            else ""
        )

        if scope == "drive":
            selected_drive_str = self.drive_var.get()
            targets = []
            if selected_drive_str.startswith("All Fixed"):
                targets = DriveDetector.get_fixed_drive_letters()
            else:
                letter = selected_drive_str.split()[0]
                targets = [letter]

            for root_dir in targets:
                if self.cancel_event.is_set():
                    break
                if not os.path.exists(root_dir):
                    continue
                for root, dirs, files in os.walk(root_dir, topdown=True):
                    if self.cancel_event.is_set():
                        dirs.clear()
                        break
                    # Prune quarantine directory from traversal
                    if quar_dir:
                        dirs[:] = [
                            d for d in dirs
                            if not os.path.normcase(os.path.abspath(os.path.join(root, d))).startswith(quar_dir)
                        ]
                    for f in files:
                        files_to_scan.append(os.path.join(root, f))
            return files_to_scan

        if scope == "files":
            raw = self.target_var.get().strip()
            if not raw:
                return []
            parts = [p.strip() for p in raw.split(";") if p.strip()]
            for p in parts:
                if os.path.isfile(p):
                    files_to_scan.append(p)
            return files_to_scan

        if scope == "folder":
            folder = self.target_var.get().strip()
            if not folder or not os.path.isdir(folder):
                return []
            for root, dirs, files in os.walk(folder, topdown=True):
                if self.cancel_event.is_set():
                    dirs.clear()
                    break
                # Prune quarantine directory from traversal
                if quar_dir:
                    dirs[:] = [
                        d for d in dirs
                        if not os.path.normcase(os.path.abspath(os.path.join(root, d))).startswith(quar_dir)
                    ]
                for f in files:
                    files_to_scan.append(os.path.join(root, f))
            return files_to_scan

        return files_to_scan

    def _scan_worker(self) -> None:
        try:
            files = self._collect_files()
            total_files = len(files)

            self.ui_queue.put(("SCAN_PREPARED", total_files))

            if total_files == 0:
                dur = time.time() - self.scan_start_time if self.scan_start_time > 0 else 0.0
                summary = ScanSummary(scanned_files=0, cancelled=self.cancel_event.is_set(), duration_seconds=dur)
                self.ui_queue.put(("SCAN_FINISHED", summary))
                return

            last_progress_time = 0.0
            last_progress_count = 0

            def on_progress(current: int, total: int, file_path: str):
                nonlocal last_progress_time, last_progress_count
                now = time.time()
                # Throttle UI progress queue messages to at most once per 50ms or every 25 files, or upon final file
                if current == total or (current - last_progress_count >= 25) or (now - last_progress_time >= 0.05):
                    last_progress_time = now
                    last_progress_count = current
                    self.ui_queue.put(("SCAN_PROGRESS", (current, total, file_path)))

            def on_detection(det: ScanDetection):
                self.ui_queue.put(("SCAN_DETECTION", det))

            summary = self.engine.scan_files(
                file_paths=files,
                progress_callback=on_progress,
                detection_callback=on_detection,
                cancel_token=self.cancel_event,
            )
            summary.duration_seconds = time.time() - self.scan_start_time if self.scan_start_time > 0 else 0.0
            self.ui_queue.put(("SCAN_FINISHED", summary))
        except Exception as exc:
            logger.error(f"Scan worker encountered an unhandled error: {exc}")
            dur = time.time() - self.scan_start_time if self.scan_start_time > 0 else 0.0
            summary = ScanSummary(scanned_files=0, error_files=1, cancelled=False, duration_seconds=dur)
            self.ui_queue.put(("SCAN_FINISHED", summary))

    def handle_ui_event(self, event_type: str, data: any) -> None:
        """Called from main thread queue processor."""
        if event_type == "SCAN_PREPARED":
            total = data
            self.progress_bar.stop()
            self.progress_bar.config(mode="determinate", maximum=max(1, total), value=0)
            self.status_label.config(text=f"Found {total} files to scan.")

        elif event_type == "SCAN_PROGRESS":
            curr, total, path = data
            self.progress_bar.config(value=curr)
            # Truncate path if too long
            display_path = path if len(path) < 70 else f"...{path[-67:]}"
            self.status_label.config(text=f"[{curr}/{total}] {display_path}")
            self.scanned_lbl.config(text=f"Scanned: {curr}")

        elif event_type == "SCAN_DETECTION":
            det: ScanDetection = data
            self.current_detections.append(det)
            self.tree.insert("", "end", values=(det.file_path, det.threat_name, det.action_taken))
            count = len(self.current_detections)
            self.threats_lbl.config(text=f"Infected: {count}", foreground="#dc3545")

        elif event_type == "SCAN_FINISHED":
            self._cancel_duration_timer()
            summary: ScanSummary = data
            self.is_scanning = False
            self.start_btn.config(state="normal")
            self.cancel_btn.config(state="disabled")

            dur = max(0.0, summary.duration_seconds)
            if dur < 60:
                elapsed = f"{dur:.1f}s"
            else:
                mins = int(dur // 60)
                secs = dur % 60
                elapsed = f"{mins}m {secs:04.1f}s"

            self.scanned_lbl.config(text=f"Scanned: {summary.scanned_files}")
            self.errors_lbl.config(text=f"Errors: {summary.error_files}")
            self.time_lbl.config(text=f"Duration: {elapsed}")

            if summary.cancelled:
                self.status_label.config(text=f"Scan cancelled by user. ({summary.scanned_files} files scanned)")
                self.on_scan_state_change("idle")
            elif summary.infected_files > 0:
                self.status_label.config(text=f"Scan complete. {summary.infected_files} threat(s) detected!")
                self.on_scan_state_change("threat")
            elif summary.scanned_files == 0:
                self.status_label.config(text="Scan complete. No matching files found to scan.")
                self.on_scan_state_change("idle")
            else:
                self.status_label.config(text="Scan complete. No threats detected.")
                self.on_scan_state_change("idle")

    def _check_and_update_threat_state(self) -> None:
        """
        Inspects all items in the detections tree.
        If no unresolved threats remain (all are Quarantined, Deleted, or Ignored),
        marks the tray icon green ('idle') again.
        """
        all_items = self.tree.get_children()
        if not all_items:
            self.on_scan_state_change("idle")
            return

        has_unresolved = False
        resolved_count = 0
        for item_id in all_items:
            vals = self.tree.item(item_id, "values")
            action = vals[2] if len(vals) > 2 else ""
            if action in ("Quarantined", "Deleted", "Ignored"):
                resolved_count += 1
            else:
                has_unresolved = True

        if not has_unresolved:
            logger.info(f"All {resolved_count} detected threats resolved. Restoring tray icon to green (idle).")
            self.on_scan_state_change("idle")
            self.threats_lbl.config(text=f"Infected: 0 (Resolved)", foreground="#28a745")
            self.status_label.config(text=f"All {resolved_count} threat(s) neutralized and removed.")

    def _quarantine_selected(self) -> None:
        selected_items = self.tree.selection()
        if not selected_items:
            # If nothing specifically selected, select all unresolved items
            selected_items = [
                i for i in self.tree.get_children()
                if self.tree.item(i, "values")[2] not in ("Quarantined", "Deleted", "Ignored")
            ]
        if not selected_items:
            messagebox.showinfo("TinyAV", "No unresolved threats to quarantine.")
            return

        quarantined_count = 0
        for item_id in selected_items:
            vals = self.tree.item(item_id, "values")
            file_path, threat_name, _ = vals
            res = self.quarantine_manager.quarantine_file(file_path, threat_name)
            if res:
                self.tree.set(item_id, "action", "Quarantined")
                quarantined_count += 1
            else:
                self.tree.set(item_id, "action", "Quarantine Failed")

        if quarantined_count > 0:
            self.ui_queue.put(("QUARANTINE_UPDATED", None))

        self._check_and_update_threat_state()
        messagebox.showinfo("TinyAV", f"Quarantined {quarantined_count} file(s).")

    def _quarantine_all(self) -> None:
        unresolved = [
            i for i in self.tree.get_children()
            if self.tree.item(i, "values")[2] not in ("Quarantined", "Deleted", "Ignored")
        ]
        if not unresolved:
            messagebox.showinfo("TinyAV", "No unresolved threats to quarantine.")
            return
        self.tree.selection_set(unresolved)
        self._quarantine_selected()

    def _delete_selected(self) -> None:
        selected_items = self.tree.selection()
        if not selected_items:
            selected_items = [
                i for i in self.tree.get_children()
                if self.tree.item(i, "values")[2] not in ("Quarantined", "Deleted", "Ignored")
            ]
        if not selected_items:
            messagebox.showinfo("TinyAV", "No unresolved threats to delete.")
            return

        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to permanently delete {len(selected_items)} selected file(s)? This action cannot be undone.",
            icon="warning",
        )
        if not confirm:
            return

        deleted_count = 0
        for item_id in selected_items:
            vals = self.tree.item(item_id, "values")
            file_path, _, _ = vals
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                self.tree.set(item_id, "action", "Deleted")
                deleted_count += 1
            except Exception as exc:
                logger.error(f"Failed to delete {file_path}: {exc}")
                self.tree.set(item_id, "action", "Delete Failed")

        self._check_and_update_threat_state()
        messagebox.showinfo("TinyAV", f"Deleted {deleted_count} file(s).")

    def _delete_all(self) -> None:
        unresolved = [
            i for i in self.tree.get_children()
            if self.tree.item(i, "values")[2] not in ("Quarantined", "Deleted", "Ignored")
        ]
        if not unresolved:
            messagebox.showinfo("TinyAV", "No unresolved threats to delete.")
            return
        self.tree.selection_set(unresolved)
        self._delete_selected()

    def _ignore_selected(self) -> None:
        selected_items = self.tree.selection()
        if not selected_items:
            selected_items = [
                i for i in self.tree.get_children()
                if self.tree.item(i, "values")[2] not in ("Quarantined", "Deleted", "Ignored")
            ]
        for item_id in selected_items:
            self.tree.set(item_id, "action", "Ignored")

        self._check_and_update_threat_state()
