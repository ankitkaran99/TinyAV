import os
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk

from app.core.logger import get_logger
from app.core.quarantine import QuarantineManager

logger = get_logger()

class QuarantineTab(ttk.Frame):
    def __init__(self, parent: ttk.Notebook, quarantine_manager: QuarantineManager):
        super().__init__(parent)
        self.quarantine_manager = quarantine_manager
        self._build_ui()
        self.refresh_items()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Header info
        header_frame = ttk.Frame(self, padding=(10, 8))
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.columnconfigure(0, weight=1)

        ttk.Label(
            header_frame,
            text="Quarantined Threats Vault",
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w")

        self.count_lbl = ttk.Label(
            header_frame,
            text="Loading vault items...",
            font=("Segoe UI", 9, "bold"),
            foreground="#555555",
        )
        self.count_lbl.grid(row=0, column=1, sticky="e")

        ttk.Label(
            header_frame,
            text="Infected files stored safely here are neutralized and renamed with metadata preserved.",
            font=("Segoe UI", 8),
            foreground="#555555",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        # Table Frame
        table_frame = ttk.Frame(self, padding=(10, 0))
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        cols = ("id", "threat", "orig_path", "date", "size")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("id", text="ID")
        self.tree.heading("threat", text="Threat Name")
        self.tree.heading("orig_path", text="Original File Location")
        self.tree.heading("date", text="Quarantined At")
        self.tree.heading("size", text="Size")

        self.tree.column("id", width=90, stretch=False)
        self.tree.column("threat", width=160)
        self.tree.column("orig_path", width=380)
        self.tree.column("date", width=140)
        self.tree.column("size", width=80, stretch=False)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # Action Buttons
        btn_frame = ttk.Frame(self, padding=(10, 8))
        btn_frame.grid(row=2, column=0, sticky="ew")

        self.restore_btn = ttk.Button(btn_frame, text="Restore Selected", command=self._restore_selected)
        self.restore_btn.pack(side="left", padx=(0, 6))

        self.delete_btn = ttk.Button(btn_frame, text="Permanently Delete", command=self._delete_selected)
        self.delete_btn.pack(side="left", padx=6)

        self.refresh_btn = ttk.Button(btn_frame, text="Refresh Vault", command=self.refresh_items)
        self.refresh_btn.pack(side="left", padx=6)

        self.open_folder_btn = ttk.Button(btn_frame, text="Open Vault Folder", command=self._open_vault_folder)
        self.open_folder_btn.pack(side="right", padx=(6, 0))

    def refresh_items(self) -> None:
        for itm in self.tree.get_children():
            self.tree.delete(itm)

        items = self.quarantine_manager.list_items()
        for item in items:
            size_kb = f"{item.file_size / 1024:.1f} KB" if item.file_size > 0 else "0 KB"
            short_id = item.id[:8]
            self.tree.insert(
                "",
                "end",
                iid=item.id,
                values=(short_id, item.threat_name, item.original_path, item.quarantine_time, size_kb),
            )

        count = len(items)
        if hasattr(self, "count_lbl"):
            if count == 0:
                self.count_lbl.config(text="Vault is empty (0 threats)", foreground="#28a745")
            elif count == 1:
                self.count_lbl.config(text="1 quarantined threat secured", foreground="#d9534f")
            else:
                self.count_lbl.config(text=f"{count} quarantined threats secured", foreground="#d9534f")

    def _restore_selected(self) -> None:
        selected_ids = self.tree.selection()
        if not selected_ids:
            messagebox.showinfo("TinyAV", "Please select a quarantined file to restore.")
            return

        confirm = messagebox.askyesno(
            "Confirm Restore",
            f"Are you sure you want to restore {len(selected_ids)} file(s) back to their original location?",
        )
        if not confirm:
            return

        restored = 0
        for item_id in selected_ids:
            if self.quarantine_manager.restore_item(item_id):
                restored += 1

        self.refresh_items()
        messagebox.showinfo("TinyAV", f"Successfully restored {restored} file(s).")

    def _delete_selected(self) -> None:
        selected_ids = self.tree.selection()
        if not selected_ids:
            messagebox.showinfo("TinyAV", "Please select a quarantined file to delete.")
            return

        confirm = messagebox.askyesno(
            "Confirm Permanent Deletion",
            f"Are you sure you want to permanently delete {len(selected_ids)} file(s) from the quarantine vault?",
            icon="warning",
        )
        if not confirm:
            return

        deleted = 0
        for item_id in selected_ids:
            if self.quarantine_manager.delete_item(item_id):
                deleted += 1

        self.refresh_items()
        messagebox.showinfo("TinyAV", f"Permanently deleted {deleted} file(s).")

    def _open_vault_folder(self) -> None:
        folder = self.quarantine_manager.quarantine_dir
        if os.path.exists(folder):
            subprocess.Popen(f'explorer "{folder}"')
        else:
            messagebox.showwarning("TinyAV", f"Vault directory does not exist: {folder}")
