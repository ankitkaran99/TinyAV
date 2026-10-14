import argparse
import os
import sys
import threading
import tkinter as tk

from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger, setup_logger
from app.core.quarantine import QuarantineManager
from app.core.updater import UpdateManager
from app.platform_win.context_menu import (
    register_context_menu_direct,
    unregister_context_menu_direct,
)
from app.ui.main_window import MainWindow
from app.ui.quick_scan_dialog import QuickScanWindow

def _install_exception_hooks(logger) -> None:
    def handle_sys_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logger.critical("Unhandled MainThread exception:", exc_info=(exc_type, exc_value, exc_traceback))

    sys.excepthook = handle_sys_exception

    if hasattr(threading, "excepthook"):
        def handle_thread_exception(args):
            logger.error(f"Unhandled exception in thread '{args.thread.name}':", exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
        threading.excepthook = handle_thread_exception

def main() -> None:
    setup_logger()
    logger = get_logger()
    _install_exception_hooks(logger)

    parser = argparse.ArgumentParser(description="TinyAV - ClamAV Antivirus Companion for Windows")
    parser.add_argument("--scan-path", type=str, help="Scan a specific file or folder directly (Context menu mode)")
    parser.add_argument("--minimized", action="store_true", help="Start directly minimized to system tray")
    parser.add_argument("--register-context-menu", action="store_true", help="Register Explorer context menu (elevated)")
    parser.add_argument("--unregister-context-menu", action="store_true", help="Unregister Explorer context menu (elevated)")
    parser.add_argument("--generate-clamav-config", type=str, help="Auto-generate optimized freshclam.conf and clamd.conf (elevated)")
    parser.add_argument("--apply-clamav-zip", nargs=2, metavar=("ZIP_PATH", "TARGET_DIR"), help="Extract ClamAV portable zip (elevated)")

    args = parser.parse_args()

    # 1. Handle elevated helper commands
    if args.register_context_menu:
        success, msg = register_context_menu_direct()
        print(f"Register context menu: {msg}")
        sys.exit(0 if success else 1)

    if args.unregister_context_menu:
        success, msg = unregister_context_menu_direct()
        print(f"Unregister context menu: {msg}")
        sys.exit(0 if success else 1)

    if args.generate_clamav_config:
        from app.core.config_generator import ClamAVConfigGenerator
        success, msg, files = ClamAVConfigGenerator.generate_configs_direct(args.generate_clamav_config)
        print(msg)
        sys.exit(0 if success else 1)

    if args.apply_clamav_zip:
        from app.core.binary_updater import ClamAVBinaryUpdater
        zip_path, target_dir = args.apply_clamav_zip
        success, msg, count = ClamAVBinaryUpdater.apply_zip_update_direct(zip_path, target_dir)
        print(msg)
        sys.exit(0 if success else 1)

    config_mgr = ConfigManager()
    engine = ClamAVEngine(config_mgr.config)
    quarantine_mgr = QuarantineManager(config_mgr.config.quarantine_dir)
    update_mgr = UpdateManager(config_mgr, engine)

    # 2. Standalone Quick Scan mode (Explorer Right-Click)
    if args.scan_path:
        target = os.path.abspath(args.scan_path)
        logger.info(f"Launching standalone QuickScan for: {target}")

        # In standalone mode, create root Tk window and hide it, showing QuickScanWindow Toplevel
        root = tk.Tk()
        root.withdraw()

        def on_close():
            root.destroy()
            sys.exit(0)

        quick_win = QuickScanWindow(
            target_path=target,
            engine=engine,
            quarantine_manager=quarantine_mgr,
            on_close=on_close,
        )
        quick_win.lift()
        quick_win.focus_force()
        root.mainloop()
        return

    # 3. Full Application GUI mode
    logger.info("Starting TinyAV Main Application GUI...")
    app = MainWindow(
        config_manager=config_mgr,
        engine=engine,
        quarantine_manager=quarantine_mgr,
        update_manager=update_mgr,
        start_minimized=args.minimized or config_mgr.config.start_minimized,
    )
    app.run()

if __name__ == "__main__":
    main()
