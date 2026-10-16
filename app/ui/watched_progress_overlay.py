import os
import tkinter as tk
from tkinter import ttk
from typing import Optional


class WatchedProgressOverlay(tk.Toplevel):
    """
    Floating progress card anchored in the bottom-right corner of the desktop
    (above the Windows taskbar and system tray). Displays real-time queue
    progress when files in watched folders are being scanned.
    """

    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.withdraw()  # Hidden by default

        self._auto_close_id: Optional[str] = None
        self._current_total = 0
        self._is_visible = False

        self._build_ui()

    def _build_ui(self) -> None:
        # Outer border frame
        self.config(bg="#30363d")

        # Main inner container
        self.container = tk.Frame(self, bg="#161b22", padx=12, pady=10)
        self.container.pack(fill="both", expand=True, padx=1, pady=1)

        # Header Row: Title + Dismiss 'X'
        header = tk.Frame(self.container, bg="#161b22")
        header.pack(fill="x", pady=(0, 4))

        self.title_icon = tk.Label(
            header,
            text="🛡️",
            font=("Segoe UI", 9),
            bg="#161b22",
            fg="#58a6ff",
        )
        self.title_icon.pack(side="left", padx=(0, 4))

        self.title_label = tk.Label(
            header,
            text="Watched Folder Scanner",
            font=("Segoe UI", 9, "bold"),
            bg="#161b22",
            fg="#f0f6fc",
        )
        self.title_label.pack(side="left")

        self.btn_close = tk.Label(
            header,
            text="✕",
            font=("Segoe UI", 8, "bold"),
            bg="#161b22",
            fg="#8b949e",
            cursor="hand2",
            padx=4,
        )
        self.btn_close.pack(side="right")
        self.btn_close.bind("<Button-1>", lambda e: self.hide())
        self.btn_close.bind("<Enter>", lambda e: self.btn_close.config(fg="#f0f6fc"))
        self.btn_close.bind("<Leave>", lambda e: self.btn_close.config(fg="#8b949e"))

        # Status & File Name Row
        self.file_label = tk.Label(
            self.container,
            text="Preparing queue...",
            font=("Segoe UI", 8),
            bg="#161b22",
            fg="#8b949e",
            anchor="w",
        )
        self.file_label.pack(fill="x", pady=(0, 2))

        # Progress bar + Count Row
        prog_row = tk.Frame(self.container, bg="#161b22")
        prog_row.pack(fill="x", pady=(2, 0))

        self.progress_bar = ttk.Progressbar(
            prog_row,
            orient="horizontal",
            mode="determinate",
            maximum=100,
        )
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self.count_label = tk.Label(
            prog_row,
            text="0%",
            font=("Segoe UI", 8, "bold"),
            bg="#161b22",
            fg="#58a6ff",
            width=6,
            anchor="e",
        )
        self.count_label.pack(side="right")

    def _reposition(self) -> None:
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = 340
        height = 96
        # 24px margin from right, 64px from bottom to clear standard Windows taskbar
        x = max(0, screen_w - width - 24)
        y = max(0, screen_h - height - 64)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def show(self) -> None:
        if self._auto_close_id:
            try:
                self.after_cancel(self._auto_close_id)
            except Exception:
                pass
            self._auto_close_id = None

        self._reposition()
        self.deiconify()
        self.attributes("-topmost", True)
        self.lift()
        self._is_visible = True

    def hide(self) -> None:
        if self._auto_close_id:
            try:
                self.after_cancel(self._auto_close_id)
            except Exception:
                pass
            self._auto_close_id = None

        self.withdraw()
        self._is_visible = False

    def update_progress(self, completed: int, total: int, current_file: str) -> None:
        # Cancel any previous close timer
        if self._auto_close_id:
            try:
                self.after_cancel(self._auto_close_id)
            except Exception:
                pass
            self._auto_close_id = None

        self._current_total = total
        pct = int((completed / total) * 100) if total > 0 else 0
        pct = max(0, min(100, pct))

        self.title_icon.config(text="🛡️", fg="#58a6ff")
        self.title_label.config(text="Watched Folder Scanner", fg="#f0f6fc")

        fname = os.path.basename(current_file) if current_file else ""
        if len(fname) > 36:
            fname = fname[:18] + "..." + fname[-15:]

        status_text = f"Scanning ({completed}/{total}): {fname}" if fname else f"Scanning queue ({completed}/{total})..."

        self.file_label.config(text=status_text, fg="#c9d1d9")
        self.count_label.config(text=f"{pct}%", fg="#58a6ff")
        self.progress_bar.config(value=pct)

        self.show()

    def on_completed(self, total: int, threats_found: int) -> None:
        if self._auto_close_id:
            try:
                self.after_cancel(self._auto_close_id)
            except Exception:
                pass
            self._auto_close_id = None

        self.progress_bar.config(value=100)

        if threats_found > 0:
            self.title_icon.config(text="⚠️", fg="#f85149")
            self.title_label.config(text="Threats Detected in Watched Folder", fg="#f85149")
            self.file_label.config(text=f"{threats_found} threat(s) neutralized and quarantined", fg="#f85149")
            self.count_label.config(text="Alert", fg="#f85149")
            close_delay = 4500
        else:
            self.title_icon.config(text="✓", fg="#3fb950")
            self.title_label.config(text="Watched Folder Scan Complete", fg="#f0f6fc")
            count_str = f"{total} file{'s' if total != 1 else ''}"
            self.file_label.config(text=f"All {count_str} verified safe and clean", fg="#3fb950")
            self.count_label.config(text="100%", fg="#3fb950")
            close_delay = 2500

        self.show()
        self._auto_close_id = self.after(close_delay, self.hide)
