import os
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

try:
    import winsound
except ImportError:
    winsound = None


class ThreatNotificationDialog(tk.Toplevel):
    """
    Prominent desktop alert dialog displayed when real-time folder monitoring
    detects and neutralizes/quarantines a malicious file.
    """

    def __init__(
        self,
        file_path: str,
        threat_name: str,
        auto_quarantined: bool,
        on_action: Optional[Callable[[], None]] = None,
        on_dismiss: Optional[Callable[[], None]] = None,
    ):
        super().__init__()
        self.file_path = file_path
        self.threat_name = threat_name
        self.auto_quarantined = auto_quarantined
        self.on_action = on_action
        self.on_dismiss = on_dismiss

        self.title("TinyAV - Threat Alert")
        self.geometry("520x240")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_dismiss_click)

        # Center on screen
        self.update_idletasks()
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()
        x = (ws // 2) - 260
        y = (hs // 2) - 130
        self.geometry(f"+{x}+{y}")

        # Ensure window appears on top of all other windows
        self.attributes("-topmost", True)
        self.lift()
        self.focus_force()

        # Play system alert sound
        if winsound and os.name == "nt":
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self._build_ui()

    def _build_ui(self) -> None:
        self.configure(bg="#ffffff")

        # Top Red/Amber Alert Banner
        banner_bg = "#dc3545" if self.auto_quarantined else "#d9534f"
        banner = tk.Frame(self, bg=banner_bg, height=44)
        banner.pack(fill="x")

        banner_text = "THREAT NEUTRALIZED & QUARANTINED" if self.auto_quarantined else "MALICIOUS THREAT DETECTED"
        lbl_title = tk.Label(
            banner,
            text=f"  [!] {banner_text}",
            font=("Segoe UI", 11, "bold"),
            fg="#ffffff",
            bg=banner_bg,
        )
        lbl_title.pack(side="left", padx=12, pady=10)

        # Body Frame
        body = tk.Frame(self, bg="#ffffff", padx=16, pady=10)
        body.pack(fill="both", expand=True)

        fname = os.path.basename(self.file_path)

        # Row 1: Threat Name
        row1 = tk.Frame(body, bg="#ffffff")
        row1.pack(fill="x", pady=2)
        tk.Label(row1, text="Threat Name:", font=("Segoe UI", 9, "bold"), width=15, anchor="w", bg="#ffffff").pack(side="left")
        tk.Label(row1, text=self.threat_name, font=("Segoe UI", 9, "bold"), fg="#dc3545", bg="#ffffff").pack(side="left")

        # Row 2: Infected File
        row2 = tk.Frame(body, bg="#ffffff")
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="Infected File:", font=("Segoe UI", 9, "bold"), width=15, anchor="w", bg="#ffffff").pack(side="left")
        tk.Label(row2, text=fname, font=("Segoe UI", 9), fg="#333333", bg="#ffffff").pack(side="left")

        # Row 3: Location
        row3 = tk.Frame(body, bg="#ffffff")
        row3.pack(fill="x", pady=2)
        tk.Label(row3, text="Location:", font=("Segoe UI", 9, "bold"), width=15, anchor="w", bg="#ffffff").pack(side="left")
        trunc_path = self.file_path if len(self.file_path) < 55 else f"...{self.file_path[-52:]}"
        tk.Label(row3, text=trunc_path, font=("Segoe UI", 8), fg="#555555", bg="#ffffff").pack(side="left")

        # Row 4: Status / Action
        row4 = tk.Frame(body, bg="#ffffff")
        row4.pack(fill="x", pady=(5, 2))
        tk.Label(row4, text="Security Action:", font=("Segoe UI", 9, "bold"), width=15, anchor="w", bg="#ffffff").pack(side="left")
        status_text = "Safely isolated and moved to Quarantine Vault." if self.auto_quarantined else "File detected! Quarantine action required."
        status_fg = "#28a745" if self.auto_quarantined else "#dc3545"
        tk.Label(row4, text=status_text, font=("Segoe UI", 9, "bold"), fg=status_fg, bg="#ffffff").pack(side="left")

        # Bottom Button Bar
        btn_bar = tk.Frame(self, bg="#f8f9fa", padx=16, pady=10)
        btn_bar.pack(fill="x", side="bottom")

        action_btn_text = "View in Quarantine Vault" if self.auto_quarantined else "Open TinyAV Scanner"
        btn_action = ttk.Button(btn_bar, text=action_btn_text, command=self._on_action_click)
        btn_action.pack(side="left", padx=(0, 6))

        btn_dismiss = ttk.Button(btn_bar, text="Dismiss", command=self._on_dismiss_click, width=12)
        btn_dismiss.pack(side="right")

    def _on_action_click(self) -> None:
        self.destroy()
        if self.on_action:
            self.on_action()

    def _on_dismiss_click(self) -> None:
        self.destroy()
        if self.on_dismiss:
            self.on_dismiss()
