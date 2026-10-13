import ctypes
import struct
import threading
import time
from typing import Callable, Dict, Optional, Set

import win32con
import win32gui
from app.core.logger import get_logger
from app.platform_win.win_drives import DriveDetector, DriveInfo

logger = get_logger()

DBT_DEVICEARRIVAL = 0x8000
DBT_DEVTYP_VOLUME = 0x00000002

class DriveWatcher:
    """
    Monitors for removable drive insertion events using a dedicated Win32 message window
    listening for WM_DEVICECHANGE / DBT_DEVICEARRIVAL.
    """

    def __init__(self, callback: Callable[[DriveInfo], None]):
        self.callback = callback
        self.hwnd: Optional[int] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._known_drives: Set[str] = set()
        self._last_event_time: Dict[str, float] = {}
        self._debounce_seconds = 3.0

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        # Initialize initial drive list
        self._known_drives = {d.letter for d in DriveDetector.get_all_drives()}
        self._thread = threading.Thread(
            target=self._run_message_loop,
            daemon=True,
            name="TinyAV-DriveWatcher",
        )
        self._thread.start()
        logger.info("DriveWatcher service started.")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        if self.hwnd:
            try:
                win32gui.PostMessage(self.hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception as exc:
                logger.debug(f"Error posting close to drive watcher window: {exc}")
        logger.info("DriveWatcher service stopped.")

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int):
        if msg == win32con.WM_DEVICECHANGE:
            if wparam == DBT_DEVICEARRIVAL:
                self._handle_device_arrival(lparam)
            return True
        elif msg == win32con.WM_DESTROY:
            win32gui.PostQuitMessage(0)
            return 0
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def _extract_drive_letter_from_lparam(self, lparam: int) -> Optional[str]:
        if not lparam:
            return None
        try:
            # DEV_BROADCAST_HDR structure: (dbch_size: DWORD, dbch_devicetype: DWORD, dbch_reserved: DWORD)
            # DEV_BROADCAST_VOLUME adds: (dbcv_unitmask: DWORD, dbcv_flags: WORD)
            header = ctypes.string_at(lparam, 16)
            _, dev_type, _, unit_mask = struct.unpack("IIII", header)
            if dev_type == DBT_DEVTYP_VOLUME and unit_mask > 0:
                for i in range(26):
                    if unit_mask & (1 << i):
                        letter = f"{chr(ord('A') + i)}:\\"
                        return letter
        except Exception as exc:
            logger.debug(f"Could not parse DEV_BROADCAST_VOLUME: {exc}")
        return None

    def _handle_device_arrival(self, lparam: int) -> None:
        time.sleep(0.5)  # Allow Windows time to mount filesystem
        target_letter = self._extract_drive_letter_from_lparam(lparam)

        current_drives = {d.letter: d for d in DriveDetector.get_all_drives()}
        candidates = []

        if target_letter and target_letter in current_drives:
            candidates.append(current_drives[target_letter])
        else:
            # Check for any newly added drives
            for letter, d_info in current_drives.items():
                if letter not in self._known_drives:
                    candidates.append(d_info)

        # Update known drives
        self._known_drives = set(current_drives.keys())

        now = time.time()
        for drive in candidates:
            # Only trigger for removable media
            if not drive.is_removable:
                continue

            last_time = self._last_event_time.get(drive.letter, 0.0)
            if now - last_time < self._debounce_seconds:
                logger.debug(f"Debounced duplicate arrival event for drive {drive.letter}")
                continue

            self._last_event_time[drive.letter] = now
            logger.info(f"Detected removable drive connection: {drive.letter} ({drive.label})")

            # Fire notification/callback in separate thread
            try:
                threading.Thread(
                    target=self.callback,
                    args=(drive,),
                    daemon=True,
                    name=f"TinyAV-DrivePrompt-{drive.letter.strip(':')}",
                ).start()
            except Exception as exc:
                logger.error(f"Error executing drive arrival callback: {exc}")

    def _run_message_loop(self) -> None:
        class_name = f"TinyAV_DriveWatcher_{int(time.time())}"
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = class_name
        wc.lpfnWndProc = self._wnd_proc
        try:
            atom = win32gui.RegisterClass(wc)
            self.hwnd = win32gui.CreateWindow(
                atom,
                class_name,
                0,
                0, 0, 0, 0,
                0, 0, 0,
                None,
            )
            win32gui.PumpMessages()
        except Exception as exc:
            logger.error(f"DriveWatcher message loop failed: {exc}")
        finally:
            if self.hwnd:
                try:
                    win32gui.DestroyWindow(self.hwnd)
                except Exception:
                    pass
            try:
                win32gui.UnregisterClass(wc.lpszClassName, None)
            except Exception:
                pass
            self.hwnd = None
