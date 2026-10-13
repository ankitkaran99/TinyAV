import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, List, Optional

from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine, ScanDetection, ScanSummary
from app.core.logger import get_logger
from app.core.quarantine import QuarantineManager
from app.platform_win.win_drives import DriveInfo

logger = get_logger()

class QuickScanWindow(tk.Toplevel):
    """
    Compact popup window used for Windows Explorer 'Scan with ClamAV' context menu
    or standalone quick scans.
    """

    def __init__(
        self,
        target_path: str,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        on_close: Optional[Callable[[], None]] = None,
    ):
        super().__init__()
        self.target_path = target_path
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.on_close_cb = on_close

        self.title("TinyAV - Quick Scan")
        self.geometry("640x440")
        self.minsize(550, 380)

        self.is_scanning = False
        self.cancel_event = threading.Event()
        self.detections: List[ScanDetection] = []
        self.ui_queue = queue.Queue()

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._process_queue)
        self.after(200, self.start_scan)

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # Header
        top_frame = ttk.Frame(self, padding=(12, 10))
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(1, weight=1)

        ttk.Label(top_frame, text="Target:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w")
        target_disp = self.target_path if len(self.target_path) < 65 else f"...{self.target_path[-62:]}"
        ttk.Label(top_frame, text=target_disp, font=("Segoe UI", 9)).grid(row=0, column=1, sticky="w", padx=6)

        # Progress
        mid_frame = ttk.Frame(self, padding=(12, 4))
        mid_frame.grid(row=1, column=0, sticky="ew")
        mid_frame.columnconfigure(0, weight=1)

        self.progress_bar = ttk.Progressbar(mid_frame, orient="horizontal", mode="indeterminate")
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=3)

        self.status_lbl = ttk.Label(mid_frame, text="Initializing scan...")
        self.status_lbl.grid(row=1, column=0, sticky="w", pady=2)

        # Detections Treeview
        tree_frame = ttk.LabelFrame(self, text="Detections", padding=(8, 6))
        tree_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=6)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        cols = ("file", "threat", "action")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("file", text="File")
        self.tree.heading("threat", text="Threat")
        self.tree.heading("action", text="Action")
        self.tree.column("file", width=340)
        self.tree.column("threat", width=140)
        self.tree.column("action", width=100)

        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # Buttons
        bot_frame = ttk.Frame(self, padding=(12, 10))
        bot_frame.grid(row=3, column=0, sticky="ew")

        self.quarantine_btn = ttk.Button(bot_frame, text="Quarantine", command=self._quarantine_selected)
        self.quarantine_btn.pack(side="left", padx=(0, 6))

        self.delete_btn = ttk.Button(bot_frame, text="Delete", command=self._delete_selected)
        self.delete_btn.pack(side="left", padx=6)

        self.cancel_btn = ttk.Button(bot_frame, text="Cancel", command=self._cancel_scan)
        self.cancel_btn.pack(side="right", padx=6)

        self.close_btn = ttk.Button(bot_frame, text="Close", command=self._on_close, state="disabled")
        self.close_btn.pack(side="right", padx=6)

    def start_scan(self) -> None:
        self.is_scanning = True
        self.progress_bar.start(10)
        threading.Thread(
            target=self._scan_thread,
            daemon=True,
            name="TinyAV-QuickScanWorker",
        ).start()

    def _collect_files(self) -> List[str]:
        files = []
        quar_dir = (
            os.path.normcase(os.path.abspath(self.quarantine_manager.quarantine_dir))
            if self.quarantine_manager and self.quarantine_manager.quarantine_dir
            else ""
        )
        if os.path.isfile(self.target_path):
            files.append(self.target_path)
        elif os.path.isdir(self.target_path):
            for root, dirs, fnames in os.walk(self.target_path, topdown=True):
                if self.cancel_event.is_set():
                    break
                if quar_dir:
                    dirs[:] = [
                        d for d in dirs
                        if not os.path.normcase(os.path.abspath(os.path.join(root, d))).startswith(quar_dir)
                    ]
                for fn in fnames:
                    files.append(os.path.join(root, fn))
        return files

    def _scan_thread(self) -> None:
        try:
            files = self._collect_files()
            total = len(files)
            self.ui_queue.put(("PREPARED", total))

            if total == 0:
                summary = ScanSummary(scanned_files=0)
                self.ui_queue.put(("FINISHED", summary))
                return

            def prog_cb(curr: int, tot: int, pth: str):
                self.ui_queue.put(("PROGRESS", (curr, tot, pth)))

            def det_cb(det: ScanDetection):
                self.ui_queue.put(("DETECTION", det))

            summary = self.engine.scan_files(
                file_paths=files,
                progress_callback=prog_cb,
                detection_callback=det_cb,
                cancel_token=self.cancel_event,
            )
            self.ui_queue.put(("FINISHED", summary))
        except Exception as exc:
            logger.error(f"QuickScan thread failed: {exc}")
            summary = ScanSummary(scanned_files=0, error_files=1)
            self.ui_queue.put(("FINISHED", summary))

    def _process_queue(self) -> None:
        try:
            while True:
                msg, data = self.ui_queue.get_nowait()
                if msg == "PREPARED":
                    total = data
                    self.progress_bar.stop()
                    self.progress_bar.config(mode="determinate", maximum=max(1, total), value=0)
                    self.status_lbl.config(text=f"Scanning {total} files...")
                elif msg == "PROGRESS":
                    curr, tot, path = data
                    self.progress_bar.config(value=curr)
                    trunc = path if len(path) < 60 else f"...{path[-57:]}"
                    self.status_lbl.config(text=f"[{curr}/{tot}] {trunc}")
                elif msg == "DETECTION":
                    det: ScanDetection = data
                    self.detections.append(det)
                    self.tree.insert("", "end", values=(det.file_path, det.threat_name, "Detected"))
                elif msg == "FINISHED":
                    summary: ScanSummary = data
                    self.is_scanning = False
                    self.cancel_btn.config(state="disabled")
                    self.close_btn.config(state="normal")
                    if summary.cancelled:
                        self.status_lbl.config(text=f"Cancelled ({summary.scanned_files} scanned)")
                    elif summary.infected_files > 0:
                        self.status_lbl.config(text=f"Completed: {summary.infected_files} threat(s) found!")
                    else:
                        self.status_lbl.config(text=f"Completed: Clean ({summary.scanned_files} files scanned)")
        except queue.Empty:
            pass

        self.after(100, self._process_queue)

    def _cancel_scan(self) -> None:
        self.cancel_event.set()
        self.engine.cancel_active_scan()
        self.status_lbl.config(text="Cancelling...")

    def _quarantine_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        for item_id in selected:
            vals = self.tree.item(item_id, "values")
            fp, threat, _ = vals
            if self.quarantine_manager.quarantine_file(fp, threat):
                self.tree.set(item_id, "action", "Quarantined")

    def _delete_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        if not messagebox.askyesno("Confirm", "Delete selected file(s)?"):
            return
        for item_id in selected:
            vals = self.tree.item(item_id, "values")
            fp, _, _ = vals
            try:
                if os.path.exists(fp):
                    os.remove(fp)
                self.tree.set(item_id, "action", "Deleted")
            except Exception:
                pass

    def _on_close(self) -> None:
        if self.is_scanning:
            self.cancel_event.set()
            self.engine.cancel_active_scan()
        self.destroy()
        if self.on_close_cb:
            self.on_close_cb()


class UsbPromptDialog(tk.Toplevel):
    """
    Non-modal popup shown when a removable drive is connected.
    """

    def __init__(
        self,
        drive_info: DriveInfo,
        config_manager: ConfigManager,
        on_scan_drive: Callable[[str], None],
    ):
        super().__init__()
        self.drive_info = drive_info
        self.config_manager = config_manager
        self.on_scan_drive = on_scan_drive

        self.title("TinyAV - Removable Drive Detected")
        self.geometry("450x180")
        self.resizable(False, False)
        self.attributes("-topmost", True)

        self._build_ui()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=(16, 14))
        frame.pack(fill="both", expand=True)

        msg = f"Removable drive connected:\nDrive {self.drive_info.letter} ({self.drive_info.label})\n\nWould you like to scan this drive for threats?"
        ttk.Label(frame, text=msg, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))

        btn_box = ttk.Frame(frame)
        btn_box.pack(fill="x", pady=4)

        ttk.Button(btn_box, text="Scan Now", command=self._scan_now, width=12).pack(side="left", padx=(0, 6))
        ttk.Button(btn_box, text="Always Scan", command=self._always_scan, width=14).pack(side="left", padx=6)
        ttk.Button(btn_box, text="Ignore", command=self.destroy, width=10).pack(side="right")

    def _scan_now(self) -> None:
        self.destroy()
        self.on_scan_drive(self.drive_info.letter)

    def _always_scan(self) -> None:
        cfg = self.config_manager.config
        remembered = dict(cfg.remembered_drives)
        remembered[self.drive_info.serial_number] = "auto_scan"
        self.config_manager.update(remembered_drives=remembered)
        self.destroy()
        self.on_scan_drive(self.drive_info.letter)
