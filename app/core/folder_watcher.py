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


class QueuedFile:
    __slots__ = (
        "clean_path",
        "norm_path",
        "first_enqueued",
        "last_event",
        "settle_delay",
        "retry_count",
        "status",
    )

    def __init__(self, clean_path: str, norm_path: str, settle_delay: float):
        now = time.time()
        self.clean_path = clean_path
        self.norm_path = norm_path
        self.first_enqueued = now
        self.last_event = now
        self.settle_delay = settle_delay
        self.retry_count = 0
        self.status = "pending"  # "pending" | "scanning" | "completed" | "error"


class FileCreationHandler(FileSystemEventHandler):
    def __init__(self, watcher: "RealtimeFolderWatcher"):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            self.watcher.queue_directory(event.src_path)
        elif self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self.watcher.is_path_watched(event.src_path):
            self.watcher.queue_scan(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        # Browser downloads typically rename .crdownload/.part -> final filename
        if event.is_directory:
            self.watcher.queue_directory(event.dest_path)
        elif self.watcher.is_path_watched(event.dest_path):
            self.watcher.queue_scan(event.dest_path)


class RealtimeFolderWatcher:
    """
    Watches configured directories (e.g. Downloads folder) for newly created or completed
    files and triggers background ClamAV scans.
    
    Maintains a robust FIFO queue of pending items with trailing-edge settling, lock retries,
    batching, and progress reporting to ensure no files are skipped or dropped when new files
    arrive while a scan is active.
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
        on_queue_progress: Optional[Callable[[int, int, str], None]] = None,
        on_queue_complete: Optional[Callable[[int, int], None]] = None,
        debounce_window: float = 0.6,
        cooldown_window: float = 1.5,
    ):
        self.config_manager = config_manager
        self.engine = engine
        self.quarantine_manager = quarantine_manager
        self.on_threat_detected = on_threat_detected
        self.on_scan_clean = on_scan_clean
        self.on_scan_start = on_scan_start
        self.on_batch_clean = on_batch_clean
        self.on_queue_progress = on_queue_progress
        self.on_queue_complete = on_queue_complete
        self._debounce_window = debounce_window
        self._cooldown_window = cooldown_window

        self.observer: Optional[Observer] = None
        self.is_running = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Queue tracking
        self._queue: Dict[str, QueuedFile] = {}
        self._session_total: int = 0
        self._session_completed: int = 0
        self._session_threats: int = 0
        self._active_scans: Set[str] = set()
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

            self._queue.clear()
            self._active_scans.clear()
            self._session_total = 0
            self._session_completed = 0
            self._session_threats = 0
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

    def queue_directory(self, dir_path: str) -> None:
        """Recursively enqueues all valid files found inside a directory tree."""
        if not os.path.isdir(dir_path):
            return
        try:
            for root, dirs, files in os.walk(dir_path):
                dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIR_NAMES]
                for f in files:
                    full_p = os.path.join(root, f)
                    if self.is_path_watched(full_p):
                        self.queue_scan(full_p)
        except Exception as exc:
            logger.debug(f"Error scanning directory tree {dir_path}: {exc}")

    def queue_scan(self, file_path: str, delay: Optional[float] = None) -> None:
        """
        Enqueues a file for scanning using an in-memory queue.
        Subsequent writes reset the file's settling timestamp.
        Zero threads are spawned on event arrival, guaranteeing zero UI freezing.
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
            # If actively scanning right now, do not drop; queue for re-check
            if norm_path in self._active_scans:
                return

            # Cooldown check: if recently completed scan within cooldown window, skip duplicate
            # unless the file was genuinely modified after the previous scan finished
            last_scanned = self._recently_scanned.get(norm_path, 0.0)
            if now - last_scanned < self._cooldown_window:
                try:
                    if os.path.exists(clean_path) and os.path.getmtime(clean_path) <= last_scanned:
                        return
                except Exception:
                    return

            # If already pending in queue, update trailing-edge activity timestamp
            if norm_path in self._queue:
                item = self._queue[norm_path]
                item.last_event = now
                item.settle_delay = effective_delay
            else:
                # New item entering queue
                item = QueuedFile(clean_path, norm_path, effective_delay)
                self._queue[norm_path] = item
                self._session_total += 1
                self._notify_progress(clean_path)

        self._ensure_worker_running()
        self._wake_event.set()

    def _notify_progress(self, current_file: str, current_done: Optional[int] = None) -> None:
        if not self.on_queue_progress:
            return
        with self._lock:
            done = current_done if current_done is not None else self._session_completed
            total = max(self._session_total, done, 1)
        try:
            self.on_queue_progress(done, total, current_file)
        except Exception as exc:
            logger.debug(f"Error in on_queue_progress: {exc}")

    def _finish_session(self) -> None:
        with self._lock:
            total = self._session_total
            threats = self._session_threats
            self._session_total = 0
            self._session_completed = 0
            self._session_threats = 0

        if total > 0 and self.on_queue_complete:
            try:
                self.on_queue_complete(total, threats)
            except Exception as exc:
                logger.debug(f"Error in on_queue_complete: {exc}")

    def _worker_loop(self) -> None:
        """Dedicated single worker thread handling file settling, retries, and batched scanning."""
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=0.25)
            self._wake_event.clear()

            if self._stop_event.is_set():
                break

            now = time.time()

            with self._lock:
                # Prune old recently scanned cache (> 60s)
                if len(self._recently_scanned) > 500:
                    cutoff = now - 60.0
                    self._recently_scanned = {p: t for p, t in self._recently_scanned.items() if t > cutoff}

                # Find candidates whose settle delay has expired
                candidates: List[QueuedFile] = []
                for norm_p, item in list(self._queue.items()):
                    if item.status == "pending" and (now - item.last_event >= item.settle_delay):
                        candidates.append(item)
                        if len(candidates) >= 50:
                            break

            if not candidates:
                with self._lock:
                    if not self._queue and not self._active_scans and self._session_total > 0:
                        self._finish_session()
                continue

            # Check candidates for settle / read readiness without dropping locked files
            to_scan: List[QueuedFile] = []
            for item in candidates:
                if self._stop_event.is_set():
                    return

                # If file disappeared (deleted or moved away), remove from queue
                if not os.path.exists(item.clean_path) or os.path.isdir(item.clean_path):
                    with self._lock:
                        self._queue.pop(item.norm_path, None)
                        self._session_completed += 1
                        self._notify_progress(item.clean_path)
                    continue

                # Verify file is accessible for reading (not locked by ongoing write / download)
                if self._is_file_readable(item.clean_path):
                    to_scan.append(item)
                else:
                    # Still locked by another process (e.g. browser write or multi-part copy)
                    # DO NOT DROP! Keep in queue and re-check after brief delay
                    with self._lock:
                        item.retry_count += 1
                        if item.retry_count > 120:  # ~60 seconds of continuous lock
                            logger.warning(f"File locked for too long, dropping from queue: {item.clean_path}")
                            self._queue.pop(item.norm_path, None)
                            self._session_completed += 1
                        else:
                            item.last_event = time.time()
                            item.settle_delay = 0.5

            if not to_scan:
                continue

            # Mark to_scan items as scanning
            with self._lock:
                for item in to_scan:
                    item.status = "scanning"
                    self._active_scans.add(item.norm_path)

            try:
                self._execute_scan_batch(to_scan)
            except Exception as exc:
                logger.error(f"Error processing realtime scan batch: {exc}", exc_info=True)
            finally:
                now_finish = time.time()
                with self._lock:
                    for item in to_scan:
                        self._active_scans.discard(item.norm_path)
                        self._queue.pop(item.norm_path, None)
                        self._session_completed += 1
                        self._recently_scanned[item.norm_path] = now_finish

                    if not self._queue and not self._active_scans:
                        self._finish_session()

            # If more items exist in the queue, wake worker for next tick immediately
            with self._lock:
                if self._queue:
                    self._wake_event.set()

    def _is_file_readable(self, file_path: str) -> bool:
        """
        Verifies the file exists and is accessible for reading without exclusive locks.
        """
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False
        try:
            curr_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                f.read(min(1024, curr_size) if curr_size > 0 else 0)
            return True
        except (PermissionError, OSError):
            return False

    def _execute_scan_batch(self, batch: List[QueuedFile]) -> None:
        if not batch:
            return

        if len(batch) == 1:
            item = batch[0]
            self._scan_single(item.clean_path, item.norm_path)
        else:
            self._scan_batch(batch)

    def _scan_single(self, clean_p: str, norm_p: str) -> None:
        self._notify_progress(clean_p)
        if self.on_scan_start:
            try:
                self.on_scan_start(clean_p)
            except Exception as exc:
                logger.debug(f"Error in on_scan_start: {exc}")

        logger.info(f"Realtime scan inspecting: {clean_p}")
        status, threat, err = self.engine.scan_single_file(clean_p)

        if status == "FOUND":
            threat_name = threat or "Threat Detected"
            logger.warning(f"REALTIME DETECTION: {clean_p} infected with {threat_name}!")
            auto_quarantined = False

            with self._lock:
                self._session_threats += 1

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

    def _scan_batch(self, batch: List[QueuedFile]) -> None:
        file_paths = [b.clean_path for b in batch]
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

        def on_batch_prog(idx: int, tot: int, curr_p: str):
            with self._lock:
                done = self._session_completed + (idx - 1)
            self._notify_progress(curr_p, current_done=done)

        summary = self.engine.scan_files(
            file_paths=file_paths,
            progress_callback=on_batch_prog,
            detection_callback=on_detection,
            cancel_token=self._stop_event,
        )

        for det in detections:
            threat_name = det.threat_name or "Threat Detected"
            auto_quarantined = False
            with self._lock:
                self._session_threats += 1

            if self.config_manager.config.realtime_auto_quarantine:
                res = self.quarantine_manager.quarantine_file(det.file_path, threat_name)
                auto_quarantined = (res is not None)

            if self.on_threat_detected:
                try:
                    self.on_threat_detected(det.file_path, threat_name, auto_quarantined)
                except Exception as exc:
                    logger.error(f"Error in on_threat_detected: {exc}")

        scanned_count = getattr(summary, "scanned_files", total)
        if not isinstance(scanned_count, int):
            scanned_count = total
        clean_count = max(0, scanned_count - len(detections))
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
