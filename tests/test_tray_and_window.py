import queue
import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.quarantine import QuarantineManager
from app.core.updater import UpdateManager
from app.ui.main_window import MainWindow
from app.ui.tray import TrayManager


def test_tray_manager_callbacks():
    show_mock = MagicMock()
    scan_mock = MagicMock()
    upd_mock = MagicMock()
    set_mock = MagicMock()
    exit_mock = MagicMock()

    tray = TrayManager(
        on_show=show_mock,
        on_scan_processes=scan_mock,
        on_update=upd_mock,
        on_settings=set_mock,
        on_exit=exit_mock,
    )

    tray._on_menu_show()
    show_mock.assert_called_once()

    tray._on_menu_scan_processes()
    scan_mock.assert_called_once()

    tray._on_menu_update()
    upd_mock.assert_called_once()

    tray._on_menu_settings()
    set_mock.assert_called_once()

    tray._on_menu_exit()
    exit_mock.assert_called_once()

    assert tray.is_alive() is False


def test_main_window_queue_processing_resilience(tmp_path):
    root = tk.Tk()
    root.withdraw()

    cfg_mgr = ConfigManager(config_path=str(tmp_path / "cfg.json"))
    engine = ClamAVEngine(cfg_mgr.config)
    quar_mgr = QuarantineManager(quarantine_dir=str(tmp_path / "quar"))
    upd_mgr = UpdateManager(cfg_mgr, engine)

    with patch("app.ui.main_window.TrayManager"):
        window = MainWindow(
            config_manager=cfg_mgr,
            engine=engine,
            quarantine_manager=quar_mgr,
            update_manager=upd_mgr,
            start_minimized=True,
        )

        # Enqueue an invalid event that would crash unshielded handlers
        window.ui_queue.put(("NONEXISTENT_CRASH_EVENT", 123))

        # Enqueue valid show event
        with patch.object(window, "show_window") as mock_show:
            window.ui_queue.put(("TRAY_ACTION", "show"))

            # Process queue - should not crash, and should execute show_window
            window._process_queue()
            mock_show.assert_called_once()

        # Clean up window
        try:
            root.destroy()
        except Exception:
            pass
