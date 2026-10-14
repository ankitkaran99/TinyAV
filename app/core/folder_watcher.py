import os
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine, ScanDetection
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
    ".temp",
}

# Directories to ignore during recursive monitoring (archive extraction metadata / caches)
IGNORED_DIR_NAMES = {
    "__macosx",
    ".git",
    ".svn",
    ".vs",
    ".vscode",
    "node_modules",
}


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
        # Browser downloads typically rename .crdownload/.part -> final filename
        if not event.is_directory and self.watcher.is_path_watched(event.dest_path):
            self.watcher.queue_scan(event.dest_path)


class RealtimeFolderWatcher:
    """
    Watches configured directories (e.g. Downloads folder) for newly created or completed
    files and triggers background ClamAV scans.
    
    Uses a single background worker loop with trailing-edge settling and batching to ensure
    large extractions (e.g. unzipping archives with hundreds of files) run efficiently with
    low CPU/RAM usage and NEVER hang or lag the host system.
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        engine: ClamAVEngine,
        quarantine_manager: QuarantineManager,
        on_threat_detected: Optional[Callable[[str, str, bool], None]] = None,
        on_scan_clean: Optional[Callable[[str], None]] = None,
        on_scan_start: Optional[Callable[[str], None]] = None,
        on_batch_clean: Optional[Callable[[int, str], None]] = None,
        debounce_window: float = 0.6,
        cooldown_window: float = 3.0,
    ):
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.on_threat_detected = on_threat_detected
        self.on_scan_clean = on_scan_clean
        self.on_scan_start = on_scan_start
        self.on_batch_clean = on_batch_clean
        self._debounce_window = debounce_window
        self._cooldown_window = cooldown_window

        self.observer: Optional[Observer] = None
        self.is_running = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Dict mapping norm_path -> (clean_path, last_modified_timestamp, delay)
        self._pending_files: Dict[str, Tuple[str, float, float]] = {}
        self._recently_scanned: Dict[str, float] = {}

    def is_path_watched(self, file_path: str) -> bool:
        """Verifies that file_path resides inside a configured watched folder and not in quarantine or ignored dirs."""
        if not file_path:
            return False

        # Strip NTFS Alternate Data Stream if present (e.g. file.exe:Zone.Identifier)
        clean_path = file_path
        drive, path_tail = os.path.splitdrive(file_path)
        if ":" in path_tail:
            clean_path = drive + path_tail.split(":", 1)[0]

        norm = os.path.normcase(os.path.abspath(clean_path))

        # Explicitly exclude quarantine directory
        quar_dir = getattr(self.quarantine_manager, "quarantine_dir", None)
        if quar_dir:
            quar_norm = os.path.normcase(os.path.abspath(quar_dir))
            if norm == quar_norm or norm.startswith(quar_norm.rstrip("\\/") + os.sep):
                return False

        # Exclude temporary and quarantine extensions
        _, ext = os.path.splitext(norm)
        if ext in TEMP_EXTENSIONS:
            return False

        # Exclude archive/extraction metadata directories
        path_parts = norm.replace("/", "\\").split("\\")
        for part in path_parts:
            if part in IGNORED_DIR_NAMES:
                return False

        for wd in self.config_manager.config.watched_directories:
            wd_norm = os.path.normcase(os.path.abspath(wd))
            if norm == wd_norm or norm.startswith(wd_norm.rstrip("\\/") + os.sep):
                return True
        return False

    def _ensure_worker_running(self) -> None:
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._worker_loop,
                    daemon=True,
                    name="TinyAV-RealtimeWorker",
                )
                self._worker_thread.start()

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                return

            cfg = self.config_manager.config
            if not cfg.realtime_watch_enabled:
                logger.info("Realtime folder monitoring is disabled in configuration.")
                return

            self._stop_event.clear()
            self._wake_event.clear()

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
                self._ensure_worker_running()
                self.is_running = True
                logger.info("Realtime folder monitor started with dedicated worker queue.")
            else:
                logger.info("No valid directories configured for realtime monitoring.")

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            self._wake_event.set()

            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

            if self.observer:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=2.0)
                    logger.info("Realtime folder monitor stopped.")
                except Exception as exc:
                    logger.error(f"Error stopping realtime monitor: {exc}")
                self.observer = None

            self._pending_files.clear()
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
        Enqueues a file for scanning using an O(1) in-memory settling queue.
        Subsequent writes reset the file's settling timestamp.
        Zero threads are created here, guaranteeing zero UI freezing or system hangs.
        """
        if not file_path:
            return

        clean_path = file_path
        drive, path_tail = os.path.splitdrive(file_path)
        if ":" in path_tail:
            clean_path = drive + path_tail.split(":", 1)[0]

        _, ext = os.path.splitext(clean_path.lower())
        if ext in TEMP_EXTENSIONS:
            return

        fname = os.path.basename(clean_path)
        if fname.startswith("~") or fname.startswith("."):
            return

        norm_path = os.path.normcase(os.path.abspath(clean_path))
        now = time.time()
        effective_delay = delay if delay is not None else self._debounce_window

        with self._lock:
            # Cooldown check: if recently completed a scan within cooldown window, skip
            last_scanned = self._recently_scanned.get(norm_path, 0.0)
            if now - last_scanned < self._cooldown_window:
                return

            # Cap pending files to prevent unbounded memory on extreme extractions
            if len(self._pending_files) > 1000:
                oldest = sorted(self._pending_files.items(), key=lambda x: x[1][1])[:300]
                for k, _ in oldest:
                    self._pending_files.pop(k, None)

            # Record / update trailing edge activity timestamp
            self._pending_files[norm_path] = (clean_path, now, effective_delay)

        self._ensure_worker_running()
        self._wake_event.set()

    def _worker_loop(self) -> None:
        """Dedicated single worker thread handling file settling and batched scanning."""
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=0.2)
            self._wake_event.clear()

            if self._stop_event.is_set():
                break

            now = time.time()
            settled_batch: List[Tuple[str, str]] = []

            with self._lock:
                if len(self._recently_scanned) > 500:
                    cutoff = now - 120.0
                    self._recently_scanned = {p: t for p, t in self._recently_scanned.items() if t > cutoff}

                ready_keys = []
                for norm_p, (clean_p, last_time, delay) in self._pending_files.items():
                    if now - last_time >= delay:
                        ready_keys.append(norm_p)
                        settled_batch.append((norm_p, clean_p))
                        if len(settled_batch) >= 50:
                            break

                for norm_p in ready_keys:
                    self._pending_files.pop(norm_p, None)

            if not settled_batch:
                continue

            try:
                self._process_settled_batch(settled_batch)
            except Exception as exc:
                logger.error(f"Error processing settled realtime batch: {exc}", exc_info=True)

            # If there are remaining settled items, trigger immediate next tick
            with self._lock:
                if any(now - t >= d for _, (_, t, d) in self._pending_files.items()):
                    self._wake_event.set()

    def _process_settled_batch(self, batch: List[Tuple[str, str]]) -> None:
        valid_files: List[Tuple[str, str]] = []
        for norm_p, clean_p in batch:
            if self._stop_event.is_set():
                return
            if not os.path.exists(clean_p) or os.path.isdir(clean_p):
                continue
            if self._wait_for_file_settle(clean_p):
                valid_files.append((norm_p, clean_p))

        if not valid_files:
            return

        if len(valid_files) == 1:
            norm_p, clean_p = valid_files[0]
            self._scan_single(clean_p, norm_p)
        else:
            self._scan_batch(valid_files)

    def _wait_for_file_settle(self, file_path: str, max_retries: int = 5, retry_delay: float = 0.15) -> bool:
        """
        Verifies the file exists and is accessible for reading without exclusive locks.
        Since debounce_window already ensured no writes occurred during the quiet period,
        this check succeeds immediately if unlocked, or retries briefly if still locked.
        """
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False

        for _ in range(max_retries):
            if self._stop_event.is_set():
                return False
            try:
                curr_size = os.path.getsize(file_path)
                with open(file_path, "rb") as f:
                    f.read(min(1024, curr_size) if curr_size > 0 else 0)
                return True
            except (PermissionError, OSError):
                time.sleep(retry_delay)

        return False

    def _scan_single(self, clean_p: str, norm_p: str) -> None:
        if self.on_scan_start:
            try:
                self.on_scan_start(clean_p)
            except Exception as exc:
                logger.debug(f"Error in on_scan_start: {exc}")

        logger.info(f"Realtime scan inspecting: {clean_p}")
        status, threat, err = self.engine.scan_single_file(clean_p)

        with self._lock:
            self._recently_scanned[norm_p] = time.time()

        if status == "FOUND":
            threat_name = threat or "Threat Detected"
            logger.warning(f"REALTIME DETECTION: {clean_p} infected with {threat_name}!")
            auto_quarantined = False

            if self.config_manager.config.realtime_auto_quarantine:
                res = self.quarantine_manager.quarantine_file(clean_p, threat_name)
                auto_quarantined = (res is not None)

            if self.on_threat_detected:
                try:
                    self.on_threat_detected(clean_p, threat_name, auto_quarantined)
                except Exception as exc:
                    logger.error(f"Error in on_threat_detected: {exc}")

        elif status == "OK":
            logger.info(f"Realtime scan clean: {clean_p}")
            if self.on_scan_clean:
                try:
                    self.on_scan_clean(clean_p)
                except Exception as exc:
                    logger.error(f"Error in on_scan_clean: {exc}")
        else:
            logger.debug(f"Realtime scan error on {clean_p}: {err}")

    def _scan_batch(self, valid_files: List[Tuple[str, str]]) -> None:
        file_paths = [clean_p for _, clean_p in valid_files]
        total = len(file_paths)
        sample_name = os.path.basename(file_paths[0])

        if self.on_scan_start:
            try:
                self.on_scan_start(f"{total} files ({sample_name}...)")
            except Exception as exc:
                logger.debug(f"Error in on_scan_start: {exc}")

        logger.info(f"Realtime batch scan inspecting {total} files starting with: {sample_name}")

        detections: List[ScanDetection] = []
        def on_detection(det: ScanDetection):
            detections.append(det)

        summary = self.engine.scan_files(
            file_paths=file_paths,
            detection_callback=on_detection,
            cancel_token=self._stop_event,
        )

        now = time.time()
        with self._lock:
            for norm_p, _ in valid_files:
                self._recently_scanned[norm_p] = now

        for det in detections:
            threat_name = det.threat_name or "Threat Detected"
            auto_quarantined = False
            if self.config_manager.config.realtime_auto_quarantine:
                res = self.quarantine_manager.quarantine_file(det.file_path, threat_name)
                auto_quarantined = (res is not None)

            if self.on_threat_detected:
                try:
                    self.on_threat_detected(det.file_path, threat_name, auto_quarantined)
                except Exception as exc:
                    logger.error(f"Error in on_threat_detected: {exc}")

        clean_count = summary.scanned_files - len(detections)
        if clean_count > 0:
            logger.info(f"Realtime batch scan clean: {clean_count}/{total} files verified safe")
            if self.on_batch_clean:
                try:
                    self.on_batch_clean(clean_count, sample_name)
                except Exception as exc:
                    logger.error(f"Error in on_batch_clean: {exc}")
            elif self.on_scan_clean:
                try:
                    self.on_scan_clean(file_paths[0])
                except Exception as exc:
                    logger.error(f"Error in on_scan_clean: {exc}")
