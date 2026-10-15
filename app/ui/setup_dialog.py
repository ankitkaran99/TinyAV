import os
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional

from app.core.auto_setup import AutoProvisioner
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine


class FirstRunSetupDialog(tk.Toplevel):
    """
    User-friendly first-run onboarding dialog that provisions ClamAV
    automatically with 1-click so novice users never have to configure anything.
    """

    def __init__(
        self,
        parent: tk.Tk,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        on_completed: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        self.config_manager = config_manager
        self.engine = engine
        self.on_completed = on_completed
        self.provisioner = AutoProvisioner(config_manager, engine)

        self.title("TinyAV - Quick Start & Setup")
        self.geometry("540x360")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._center_window(parent)
        self._build_ui()

    def _center_window(self, parent: tk.Tk) -> None:
        self.update_idletasks()
        try:
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            w = 540
            h = 360
            x = px + (pw - w) // 2
            y = py + (ph - h) // 2
            self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=(24, 20))
        container.pack(fill="both", expand=True)

        # Header title
        title_lbl = ttk.Label(
            container,
            text="🛡️ Welcome to TinyAV",
            font=("Segoe UI", 16, "bold"),
            foreground="#007acc",
        )
        title_lbl.pack(anchor="w", pady=(0, 6))

        # Description
        desc_text = (
            "TinyAV uses the official open-source ClamAV antivirus engine to protect "
            "your files, downloads, and system from malware and threats.\n\n"
            "ClamAV was not detected on this PC. TinyAV can automatically download, "
            "install, and configure everything for you out-of-the-box in 1 click."
        )
        desc_lbl = ttk.Label(container, text=desc_text, wraplength=490, justify="left")
        desc_lbl.pack(anchor="w", pady=(0, 14))

        # Destination card
        dest_card = ttk.LabelFrame(container, text="Installation Location", padding=(10, 8))
        dest_card.pack(fill="x", pady=(0, 14))

        default_dir = self.provisioner.get_default_install_dir()
        ttk.Label(
            dest_card,
            text=f"📁 {default_dir}",
            font=("Segoe UI", 9, "italic"),
            foreground="#333333",
        ).pack(anchor="w")

        # Progress elements (initially hidden)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.prog_bar = ttk.Progressbar(container, variable=self.progress_var, maximum=100.0)

        self.status_lbl = ttk.Label(
            container,
            text="Ready to install.",
            font=("Segoe UI", 9),
            foreground="#555555",
        )

        # Action buttons
        self.btn_box = ttk.Frame(container)
        self.btn_box.pack(fill="x", side="bottom", pady=(10, 0))

        self.manual_btn = ttk.Button(self.btn_box, text="Configure Manually", command=self._on_skip)
        self.manual_btn.pack(side="left")

        self.install_btn = ttk.Button(
            self.btn_box,
            text="⚡ Set Up ClamAV Automatically (1-Click)",
            command=self._start_provisioning,
            width=36,
        )
        self.install_btn.pack(side="right")

    def _start_provisioning(self) -> None:
        self.install_btn.config(state="disabled")
        self.manual_btn.config(state="disabled")

        self.status_lbl.pack(fill="x", side="bottom", pady=(4, 6))
        self.prog_bar.pack(fill="x", side="bottom", pady=(4, 4))
        self.status_lbl.config(text="Starting automatic setup...", foreground="#007acc")

        def progress_cb(msg: str, pct: float):
            def _update():
                self.progress_var.set(pct)
                self.status_lbl.config(text=msg)
            self.after(0, _update)

        def completion_cb(ok: bool, msg: str):
            def _finish():
                if ok:
                    self.status_lbl.config(text="✓ Setup complete! TinyAV is fully active.", foreground="#28a745")
                    self.install_btn.config(text="Finish", state="normal", command=self._on_success)
                    if self.on_completed:
                        self.on_completed()
                    messagebox.showinfo("TinyAV Ready", "ClamAV engine has been installed and configured!\nTinyAV is now protecting your computer.")
                    self.destroy()
                else:
                    self.status_lbl.config(text=f"Setup encountered an issue: {msg}", foreground="#dc3545")
                    self.install_btn.config(text="Retry", state="normal")
                    self.manual_btn.config(state="normal")
                    messagebox.showerror("Setup Error", f"Could not complete automatic setup:\n{msg}\n\nYou can configure ClamAV manually in the Settings tab.")
            self.after(0, _finish)

        self.provisioner.run_provisioning_async(
            target_dir=None,
            progress_callback=progress_cb,
            completion_callback=completion_cb,
        )

    def _on_success(self) -> None:
        if self.on_completed:
            self.on_completed()
        self.destroy()

    def _on_skip(self) -> None:
        self.destroy()
