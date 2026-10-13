import threading
from typing import Callable, Optional

import pystray
from pystray import Menu, MenuItem
from app.core.logger import get_logger
from app.ui.icons import IconFactory

logger = get_logger()

class TrayManager:
    def __init__(
        self,
        on_show: Callable[[], None],
        on_scan_processes: Callable[[], None],
        on_update: Callable[[], None],
        on_settings: Callable[[], None],
        on_exit: Callable[[], None],
    ):
        self.on_show = on_show
        self.on_scan_processes = on_scan_processes
        self.on_update = on_update
        self.on_settings = on_settings
        self.on_exit = on_exit

        self.current_state = "idle"
        self.icon: Optional[pystray.Icon] = None
        self._thread: Optional[threading.Thread] = None

    def _create_menu(self) -> Menu:
        return Menu(
            MenuItem("Open TinyAV", lambda: self.on_show(), default=True),
            MenuItem("Scan Running Process Files", lambda: self.on_scan_processes()),
            MenuItem("Update Virus Definitions", lambda: self.on_update()),
            MenuItem("Settings", lambda: self.on_settings()),
            Menu.SEPARATOR,
            MenuItem("Exit TinyAV", lambda: self.on_exit()),
        )

    def start(self) -> None:
        if self.icon:
            return

        image = IconFactory.get_icon(self.current_state)
        self.icon = pystray.Icon(
            name="TinyAV",
            icon=image,
            title="TinyAV - Protected",
            menu=self._create_menu(),
        )

        self._thread = threading.Thread(
            target=self.icon.run,
            daemon=True,
            name="TinyAV-TrayThread",
        )
        self._thread.start()
        logger.info("Pystray system tray started.")

    def stop(self) -> None:
        if self.icon:
            try:
                self.icon.stop()
            except Exception as exc:
                logger.debug(f"Error stopping tray icon: {exc}")
            self.icon = None
            logger.info("Pystray system tray stopped.")

    def set_state(self, state: str, custom_tooltip: str = "") -> None:
        self.current_state = state
        if not self.icon:
            return

        try:
            self.icon.icon = IconFactory.get_icon(state)
            if custom_tooltip:
                self.icon.title = f"TinyAV - {custom_tooltip}"
            elif state == "idle":
                self.icon.title = "TinyAV - Idle (Protected)"
            elif state == "scanning":
                self.icon.title = "TinyAV - Scanning in progress..."
            elif state == "updating":
                self.icon.title = "TinyAV - Updating definitions..."
            elif state == "threat":
                self.icon.title = "TinyAV - Threats Detected!"
        except Exception as exc:
            logger.debug(f"Failed to update tray icon state: {exc}")

    def notify(self, title: str, message: str) -> None:
        """Sends a Windows toast/balloon notification through pystray."""
        if not self.icon:
            return
        try:
            self.icon.notify(message, title)
        except Exception as exc:
            logger.debug(f"Failed to show tray notification: {exc}")
