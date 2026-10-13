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
TEMP_EXTENSIONS = {".crdownload", ".tmp", ".part", ".partial", ".downloading", ".opdownload", ".quarantine"}

class FileCreationHandler(FileSystemEventHandler):
    def __init__(self, watcher: "RealtimeFolderWatcher"):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        # Browser downloads typically rename .crdownload -> final filename
        # Ensure destination path is still within a watched folder (not moved to quarantine/trash)
        if not event.is_directory and self.watcher.is_path_watched(event.dest_path):
            self.watcher.queue_scan(event.dest_path)


class RealtimeFolderWatcher:
    """
    Watches configured directories (e.g. Downloads folder) for newly created or completed
    files and triggers immediate background ClamAV scans.
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        on_threat_detected: Optional[Callable[[str, str, bool], None]] = None,
        on_scan_clean: Optional[Callable[[str], None]] = None,
    ):
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.on_threat_detected = on_threat_detected
        self.on_scan_clean = on_scan_clean

        self.observer: Optional[Observer] = None
        self.is_running = False
        self._lock = threading.RLock()
        self._recently_scanned: Dict[str, float] = {}
        self._debounce_window = 3.0

    def is_path_watched(self, file_path: str) -> bool:
        """Verifies that file_path resides inside a configured watched folder and not in quarantine."""
        if not file_path:
            return False
        norm = os.path.normcase(os.path.abspath(file_path))

        # Explicitly exclude quarantine directory
        if self.quarantine_manager and self.quarantine_manager.quarantine_dir:
            quar_norm = os.path.normcase(os.path.abspath(self.quarantine_manager.quarantine_dir))
            if norm.startswith(quar_norm):
                return False

        # Exclude temporary and quarantine extensions
        _, ext = os.path.splitext(norm)
        if ext in TEMP_EXTENSIONS:
            return False

        for wd in self.config_manager.config.watched_directories:
            wd_norm = os.path.normcase(os.path.abspath(wd))
            if norm.startswith(wd_norm):
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
                        self.observer.schedule(handler, dir_path, recursive=False)
                        logger.info(f"Realtime monitor watching directory: {dir_path}")
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

    def queue_scan(self, file_path: str) -> None:
        # Ignore temp files
        _, ext = os.path.splitext(file_path.lower())
        if ext in TEMP_EXTENSIONS:
            return

        norm_path = os.path.normcase(os.path.abspath(file_path))
        now = time.time()

        with self._lock:
            # Periodically prune stale debounce cache entries
            if len(self._recently_scanned) > 200:
                cutoff = now - 60.0
                self._recently_scanned = {p: t for p, t in self._recently_scanned.items() if t > cutoff}

            last_scanned = self._recently_scanned.get(norm_path, 0.0)
            if now - last_scanned < self._debounce_window:
                return
            self._recently_scanned[norm_path] = now

        threading.Thread(
            target=self._scan_file_worker,
            args=(file_path,),
            daemon=True,
            name=f"TinyAV-RTScan-{os.path.basename(file_path)}",
        ).start()

    def _wait_for_file_settle(self, file_path: str, max_retries: int = 6) -> bool:
        """Waits for browser/downloader to finish writing and release locks."""
        prev_size = -1
        for _ in range(max_retries):
            if not os.path.exists(file_path):
                return False
            try:
                curr_size = os.path.getsize(file_path)
                # Check if file can be opened for reading
                with open(file_path, "rb") as f:
                    f.read(min(1024, curr_size) if curr_size > 0 else 0)
                # If non-empty and size has stabilized, file is ready
                if curr_size > 0 and curr_size == prev_size:
                    return True
                prev_size = curr_size
            except (PermissionError, OSError):
                pass
            time.sleep(0.5)
        return os.path.exists(file_path)

    def _scan_file_worker(self, file_path: str) -> None:
        # Wait a short moment for downloader flush
        time.sleep(0.5)

        if not self._wait_for_file_settle(file_path):
            logger.debug(f"File was busy or deleted before scan could run: {file_path}")
            return

        logger.info(f"Realtime scan inspecting: {file_path}")
        status, threat, err = self.engine.scan_single_file(file_path)

        if status == "FOUND":
            threat_name = threat or "Threat Detected"
            logger.warning(f"REALTIME DETECTION: {file_path} infected with {threat_name}!")
            auto_quarantined = False

            if self.config_manager.config.realtime_auto_quarantine:
                res = self.quarantine_manager.quarantine_file(file_path, threat_name)
                auto_quarantined = (res is not None)

            if self.on_threat_detected:
                self.on_threat_detected(file_path, threat_name, auto_quarantined)

        elif status == "OK":
            logger.info(f"Realtime scan clean: {file_path}")
            if self.on_scan_clean and self.config_manager.config.notify_on_clean:
                self.on_scan_clean(file_path)
        else:
            logger.debug(f"Realtime scan error on {file_path}: {err}")
