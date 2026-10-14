import os
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger
from app.core.quarantine import QuarantineManager

logger = get_logger()

# Common browser download temp extensions to ignore until finalized, plus quarantine extension
TEMP_EXTENSIONS = {
    ".crdownload",   # Google Chrome, Microsoft Edge, Brave, Vivaldi
    ".tmp",          # Generic temp files
    ".part",         # Mozilla Firefox
    ".partial",      # Internet Explorer / wget
    ".downloading",  # Torrent clients / generic downloaders
    ".opdownload",   # Opera browser
    ".quarantine",   # TinyAV quarantine files
    ".!ut",          # uTorrent
    ".download",     # Safari / Chrome Mac / generic
}


class FileCreationHandler(FileSystemEventHandler):
    def __init__(self, watcher: "RealtimeFolderWatcher"):
        super().__init__()
        self.watcher = watcher

    def _queue_directory_files(self, dir_path: str) -> None:
        """Walks newly created or moved directories and queues eligible files."""
        try:
            if not os.path.isdir(dir_path):
                return
            for root, _, files in os.walk(dir_path):
                for f in files:
                    full_p = os.path.join(root, f)
                    if self.watcher.is_path_watched(full_p):
                        self.watcher.queue_scan(full_p)
        except Exception as exc:
            logger.debug(f"Error enumerating directory '{dir_path}': {exc}")

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            self._queue_directory_files(event.src_path)
        elif self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        # Browser downloads typically rename .crdownload/.part -> final filename
        if event.is_directory:
            self._queue_directory_files(event.dest_path)
        elif self.watcher.is_path_watched(event.dest_path):
            self.watcher.queue_scan(event.dest_path)


class RealtimeFolderWatcher:
    """
    Watches configured directories (e.g. Downloads folder) for newly created or completed
    files and triggers immediate background ClamAV scans using trailing-edge debouncing
    to let downloads settle and unlock before scanning.
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        on_threat_detected: Optional[Callable[[str, str, bool], None]] = None,
        on_scan_clean: Optional[Callable[[str], None]] = None,
        on_scan_start: Optional[Callable[[str], None]] = None,
        debounce_window: float = 0.6,
        cooldown_window: float = 3.0,
    ):
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.on_threat_detected = on_threat_detected
        self.on_scan_clean = on_scan_clean
        self.on_scan_start = on_scan_start
        self._debounce_window = debounce_window
        self._cooldown_window = cooldown_window

        self.observer: Optional[Observer] = None
        self.is_running = False
        self._lock = threading.RLock()
        self._pending_timers: Dict[str, threading.Timer] = {}
        self._recently_scanned: Dict[str, float] = {}

    def is_path_watched(self, file_path: str) -> bool:
        """Verifies that file_path resides inside a configured watched folder and not in quarantine."""
        if not file_path:
            return False

        # Strip NTFS Alternate Data Stream if present (e.g. file.exe:Zone.Identifier)
        clean_path = file_path
        drive, path_tail = os.path.splitdrive(file_path)
        if ":" in path_tail:
            clean_path = drive + path_tail.split(":", 1)[0]

        norm = os.path.normcase(os.path.abspath(clean_path))

        # Explicitly exclude quarantine directory
        if self.quarantine_manager and self.quarantine_manager.quarantine_dir:
            quar_norm = os.path.normcase(os.path.abspath(self.quarantine_manager.quarantine_dir))
            if norm == quar_norm or norm.startswith(quar_norm.rstrip("\\/") + os.sep):
                return False

        # Exclude temporary and quarantine extensions
        _, ext = os.path.splitext(norm)
        if ext in TEMP_EXTENSIONS:
            return False

        for wd in self.config_manager.config.watched_directories:
            wd_norm = os.path.normcase(os.path.abspath(wd))
            if norm == wd_norm or norm.startswith(wd_norm.rstrip("\\/") + os.sep):
                return True
        return False

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                return

            cfg = self.config_manager.config
            if not cfg.realtime_watch_enabled:
                logger.info("Realtime folder monitoring is disabled in configuration.")
                return

            self.observer = Observer()
            handler = FileCreationHandler(self)
            watched_any = False

            for dir_path in cfg.watched_directories:
                if os.path.isdir(dir_path):
                    try:
                        self.observer.schedule(handler, dir_path, recursive=True)
                        logger.info(f"Realtime monitor watching directory (recursive): {dir_path}")
                        watched_any = True
                    except Exception as exc:
                        logger.error(f"Failed to watch directory {dir_path}: {exc}")

            if watched_any:
                self.observer.start()
                self.is_running = True
                logger.info("Realtime folder monitor started.")
            else:
                logger.info("No valid directories configured for realtime monitoring.")

    def stop(self) -> None:
        with self._lock:
            # Cancel all active debounce timers
            for timer in self._pending_timers.values():
                try:
                    timer.cancel()
                except Exception:
                    pass
            self._pending_timers.clear()

            if not self.is_running or not self.observer:
                return
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
                logger.info("Realtime folder monitor stopped.")
            except Exception as exc:
                logger.error(f"Error stopping realtime monitor: {exc}")
            self.observer = None
            self.is_running = False

    def restart(self) -> None:
        self.stop()
        self.start()

    def update_directories(self, directories: List[str], enabled: bool) -> None:
        self.config_manager.update(
            watched_directories=directories,
            realtime_watch_enabled=enabled,
        )
        self.restart()

    def queue_scan(self, file_path: str, delay: Optional[float] = None) -> None:
        """
        Schedules a scan using a trailing-edge timer. Subsequent writes or modify
        events reset the timer until the file quiet period elapses (download finishes).
        """
        if not file_path:
            return

        # Strip NTFS Alternate Data Stream if present
        clean_path = file_path
        drive, path_tail = os.path.splitdrive(file_path)
        if ":" in path_tail:
            clean_path = drive + path_tail.split(":", 1)[0]

        _, ext = os.path.splitext(clean_path.lower())
        if ext in TEMP_EXTENSIONS:
            return

        norm_path = os.path.normcase(os.path.abspath(clean_path))
        now = time.time()
        effective_delay = delay if delay is not None else self._debounce_window

        with self._lock:
            # 1. Cooldown check: if recently completed a scan, avoid duplicate loop
            last_scanned = self._recently_scanned.get(norm_path, 0.0)
            if now - last_scanned < self._cooldown_window:
                return

            # Periodically prune stale debounce cache entries
            if len(self._recently_scanned) > 200:
                cutoff = now - 60.0
                self._recently_scanned = {p: t for p, t in self._recently_scanned.items() if t > cutoff}

            # 2. Reset / Debounce trailing-edge timer for this file
            existing_timer = self._pending_timers.pop(norm_path, None)
            if existing_timer:
                try:
                    existing_timer.cancel()
                except Exception:
                    pass

            timer = threading.Timer(
                effective_delay,
                self._on_debounce_timer_fired,
                args=(clean_path, norm_path),
            )
            timer.daemon = True
            self._pending_timers[norm_path] = timer
            timer.start()

    def _on_debounce_timer_fired(self, clean_path: str, norm_path: str) -> None:
        with self._lock:
            self._pending_timers.pop(norm_path, None)

        threading.Thread(
            target=self._scan_file_worker,
            args=(clean_path, norm_path),
            daemon=True,
            name=f"TinyAV-RTScan-{os.path.basename(clean_path)}",
        ).start()

    def _wait_for_file_settle(self, file_path: str, max_retries: int = 10, retry_delay: float = 0.25) -> bool:
        """
        Waits for downloader/browser to finish writing and release locks.
        Verifies the file exists, can be opened for reading without sharing violations,
        and its size remains steady across checks.
        """
        prev_size = -1
        stable_count = 0

        for _ in range(max_retries):
            if not os.path.exists(file_path):
                return False
            try:
                curr_size = os.path.getsize(file_path)
                # Try opening file in read mode to check if write lock was released
                with open(file_path, "rb") as f:
                    f.read(min(1024, curr_size) if curr_size > 0 else 0)

                if curr_size == prev_size:
                    stable_count += 1
                    if stable_count >= 1:
                        return True
                else:
                    stable_count = 0
                    prev_size = curr_size
            except (PermissionError, OSError):
                # File is currently locked exclusively by the writer
                stable_count = 0

            time.sleep(retry_delay)

        # Fallback check after retries
        try:
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    f.read(1)
                return True
        except (PermissionError, OSError):
            return False

        return False

    def _scan_file_worker(self, file_path: str, norm_path: Optional[str] = None) -> None:
        if not norm_path:
            norm_path = os.path.normcase(os.path.abspath(file_path))

        # Check if file has settled and write locks are released
        if not self._wait_for_file_settle(file_path):
            logger.debug(f"File was busy or deleted before scan could run: {file_path}")
            return

        if self.on_scan_start:
            try:
                self.on_scan_start(file_path)
            except Exception as exc:
                logger.debug(f"Error in on_scan_start callback: {exc}")

        logger.info(f"Realtime scan inspecting: {file_path}")
        status, threat, err = self.engine.scan_single_file(file_path)

        with self._lock:
            self._recently_scanned[norm_path] = time.time()

        if status == "FOUND":
            threat_name = threat or "Threat Detected"
            logger.warning(f"REALTIME DETECTION: {file_path} infected with {threat_name}!")
            auto_quarantined = False

            if self.config_manager.config.realtime_auto_quarantine:
                res = self.quarantine_manager.quarantine_file(file_path, threat_name)
                auto_quarantined = (res is not None)

            if self.on_threat_detected:
                try:
                    self.on_threat_detected(file_path, threat_name, auto_quarantined)
                except Exception as exc:
                    logger.error(f"Error in on_threat_detected callback: {exc}")

        elif status == "OK":
            logger.info(f"Realtime scan clean: {file_path}")
            if self.on_scan_clean:
                try:
                    self.on_scan_clean(file_path)
                except Exception as exc:
                    logger.error(f"Error in on_scan_clean callback: {exc}")
        else:
            logger.debug(f"Realtime scan error on {file_path}: {err}")
