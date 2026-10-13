import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

import clamd
from app.core.config import AppConfig
from app.core.logger import get_logger

logger = get_logger()

class EngineMode(str, Enum):
    CLAMD = "clamd"
    CLAMSCAN = "clamscan"
    UNAVAILABLE = "unavailable"

@dataclass
class ScanDetection:
    file_path: str
    threat_name: str
    action_taken: str = "Detected"  # "Detected", "Quarantined", "Deleted", "Ignored"

@dataclass
class ScanSummary:
    scanned_files: int = 0
    infected_files: int = 0
    error_files: int = 0
    detections: List[ScanDetection] = field(default_factory=list)
    cancelled: bool = False
    duration_seconds: float = 0.0

# Regex for parsing clamscan line output:
# Examples:
# C:\path\to\eicar.com: Win.Test.EICAR_HDB-1 FOUND
# C:\path\to\clean.txt: OK
# C:\path\to\locked.bin: Can't open file ERROR
CLAMSCAN_FOUND_REGEX = re.compile(r"^(.*?):\s+(.*?)\s+FOUND$", re.IGNORECASE)
CLAMSCAN_OK_REGEX = re.compile(r"^(.*?):\s+OK$", re.IGNORECASE)
CLAMSCAN_ERROR_REGEX = re.compile(r"^(.*?):\s+(.*?)\s+ERROR$", re.IGNORECASE)

class ClamAVEngine:
    def __init__(self, config: AppConfig):
        self.config = config
        self.clamd_client: Optional[clamd.ClamdNetworkSocket] = None
        self.mode = EngineMode.UNAVAILABLE
        self.engine_version = "Unknown"
        self.clamscan_path: Optional[str] = None
        self.freshclam_path: Optional[str] = None
        self.clamd_path: Optional[str] = None
        self._active_proc: Optional[subprocess.Popen] = None
        self.refresh_engine()

    def cancel_active_scan(self) -> None:
        """Immediately terminates any running clamscan subprocess."""
        if self._active_proc:
            try:
                self._active_proc.terminate()
            except Exception:
                pass
            self._active_proc = None

    def find_binary(self, binary_name: str) -> Optional[str]:
        # 1. Custom configured bin directory
        if self.config.clamav_bin_dir:
            candidate = os.path.join(self.config.clamav_bin_dir, f"{binary_name}.exe")
            if os.path.isfile(candidate):
                return candidate
            candidate_raw = os.path.join(self.config.clamav_bin_dir, binary_name)
            if os.path.isfile(candidate_raw):
                return candidate_raw

        # 2. PATH
        found = shutil.which(f"{binary_name}.exe") or shutil.which(binary_name)
        if found:
            return found

        # 3. Well-known Windows paths
        common_dirs = [
            r"C:\Program Files\ClamAV",
            r"C:\Program Files (x86)\ClamAV",
            r"C:\ClamAV",
            r"C:\tools\clamav",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\ClamAV"),
            os.path.expandvars(r"%USERPROFILE%\scoop\apps\clamav\current"),
        ]
        for d in common_dirs:
            p = os.path.join(d, f"{binary_name}.exe")
            if os.path.isfile(p):
                return p
        return None

    def refresh_engine(self) -> EngineMode:
        """Detect available engine (clamd daemon vs clamscan CLI)."""
        self.clamscan_path = self.find_binary("clamscan")
        self.freshclam_path = self.find_binary("freshclam")
        self.clamd_path = self.find_binary("clamd")

        # Check clamd daemon first if preferred
        if self.config.prefer_clamd:
            try:
                client = clamd.ClamdNetworkSocket(
                    host=self.config.clamd_host,
                    port=self.config.clamd_port,
                    timeout=2.0,
                )
                if client.ping() == "PONG":
                    self.clamd_client = client
                    self.mode = EngineMode.CLAMD
                    try:
                        self.engine_version = client.version()
                    except Exception:
                        self.engine_version = "clamd (connected)"
                    logger.info(f"ClamAV daemon active at {self.config.clamd_host}:{self.config.clamd_port} ({self.engine_version})")
                    return self.mode
            except Exception as exc:
                logger.debug(f"clamd daemon not responding on {self.config.clamd_host}:{self.config.clamd_port}: {exc}")
                self.clamd_client = None

        # Fallback to clamscan executable
        if self.clamscan_path:
            self.mode = EngineMode.CLAMSCAN
            try:
                out = subprocess.check_output(
                    [self.clamscan_path, "--version"],
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                self.engine_version = out.strip().split("\n")[0]
            except Exception as exc:
                self.engine_version = "ClamScan CLI"
                logger.debug(f"Could not get clamscan version: {exc}")
            logger.info(f"ClamAV using clamscan CLI at {self.clamscan_path} ({self.engine_version})")
            return self.mode

        self.mode = EngineMode.UNAVAILABLE
        self.engine_version = "Not detected"
        logger.warning("No ClamAV engine (clamd or clamscan.exe) detected")
        return self.mode

    @staticmethod
    def parse_clamscan_line(line: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Parses a single line from clamscan output.
        Returns: (status, file_path, threat_name, error_msg)
        status: 'FOUND' | 'OK' | 'ERROR' | None
        """
        line = line.strip()
        if not line:
            return None, None, None, None

        m_found = CLAMSCAN_FOUND_REGEX.match(line)
        if m_found:
            return "FOUND", m_found.group(1).strip(), m_found.group(2).strip(), None

        m_ok = CLAMSCAN_OK_REGEX.match(line)
        if m_ok:
            return "OK", m_ok.group(1).strip(), None, None

        m_err = CLAMSCAN_ERROR_REGEX.match(line)
        if m_err:
            return "ERROR", m_err.group(1).strip(), None, m_err.group(2).strip()

        return None, None, None, None

    def scan_single_file(self, file_path: str) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Scans a single file using the active engine.
        Returns: (status: 'OK' | 'FOUND' | 'ERROR', threat_name, error_msg)
        """
        if not os.path.isfile(file_path):
            return "ERROR", None, f"File does not exist: {file_path}"

        if self.mode == EngineMode.CLAMD and self.clamd_client:
            try:
                # Try instream first for cross-user permission safety on Windows
                with open(file_path, "rb") as f:
                    res = self.clamd_client.instream(f)
                # Response shape: {'stream': ('FOUND', 'threat')} or {'stream': ('OK', None)}
                if "stream" in res:
                    st, threat = res["stream"]
                    if st == "FOUND":
                        return "FOUND", threat, None
                    elif st == "OK":
                        return "OK", None, None
                    else:
                        return "ERROR", None, f"clamd returned: {st}"
            except PermissionError as exc:
                return "ERROR", None, f"Permission denied / file in use: {exc}"
            except Exception as exc:
                logger.debug(f"clamd instream scan failed for {file_path}: {exc}, falling back to clamscan")

        # Fallback to clamscan.exe
        if self.clamscan_path:
            try:
                cmd = [self.clamscan_path, "--stdout", "--no-summary", file_path]
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    cwd=os.path.dirname(self.clamscan_path),
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                self._active_proc = proc
                stdout, stderr = proc.communicate(timeout=120)
                stdout = (stdout or "").strip()
                for line in stdout.splitlines():
                    st, path, threat, err = self.parse_clamscan_line(line)
                    if st == "FOUND":
                        return "FOUND", threat, None
                    elif st == "ERROR":
                        return "ERROR", None, err
                    elif st == "OK":
                        return "OK", None, None
                # Check return code: 0 = clean, 1 = infected, 2 = error
                if proc.returncode == 0:
                    return "OK", None, None
                elif proc.returncode == 1:
                    return "FOUND", "Unknown Threat", None
                else:
                    return "ERROR", None, f"Exit code {proc.returncode}: {(stderr or '').strip()}"
            except Exception as exc:
                return "ERROR", None, str(exc)
            finally:
                self._active_proc = None

        return "ERROR", None, "ClamAV engine is not installed or available."

    def scan_files(
        self,
        file_paths: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        detection_callback: Optional[Callable[[ScanDetection], None]] = None,
        cancel_token: Optional[threading.Event] = None,
    ) -> ScanSummary:
        """
        Scans a list of files with live progress reporting.
        If using clamscan CLI on multiple files, uses batch streaming with --file-list
        to avoid reloading virus signatures per file (up to 50x-100x faster).
        """
        start_time = time.time()
        summary = ScanSummary()
        total = len(file_paths)
        if total == 0:
            summary.duration_seconds = time.time() - start_time
            return summary

        # If clamscan CLI is active and we have multiple files, use batch streaming
        if self.mode == EngineMode.CLAMSCAN and self.clamscan_path and total > 1:
            summary = self._scan_files_batch_clamscan(
                file_paths=file_paths,
                progress_callback=progress_callback,
                detection_callback=detection_callback,
                cancel_token=cancel_token,
            )
            summary.duration_seconds = time.time() - start_time
            return summary

        # File-by-file scanning (used for clamd socket or single files)
        for idx, file_path in enumerate(file_paths, start=1):
            if cancel_token and cancel_token.is_set():
                summary.cancelled = True
                break

            if progress_callback:
                progress_callback(idx, total, file_path)

            status, threat, err = self.scan_single_file(file_path)
            if status == "FOUND":
                summary.scanned_files += 1
                summary.infected_files += 1
                det = ScanDetection(file_path=file_path, threat_name=threat or "Threat")
                summary.detections.append(det)
                if detection_callback:
                    detection_callback(det)
            elif status == "OK":
                summary.scanned_files += 1
            else:
                summary.error_files += 1

        summary.duration_seconds = time.time() - start_time
        return summary

    def _scan_files_batch_clamscan(
        self,
        file_paths: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]],
        detection_callback: Optional[Callable[[ScanDetection], None]],
        cancel_token: Optional[threading.Event],
    ) -> ScanSummary:
        import tempfile

        summary = ScanSummary()
        total = len(file_paths)
        temp_list = None

        try:
            # Write target file list to a temporary file
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as tf:
                temp_list = tf.name
                for p in file_paths:
                    tf.write(f"{p}\n")

            cmd = [
                self.clamscan_path,
                "--stdout",
                "--no-summary",
                f"--file-list={temp_list}",
            ]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=os.path.dirname(self.clamscan_path),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            self._active_proc = proc

            scanned = 0
            while True:
                if cancel_token and cancel_token.is_set():
                    summary.cancelled = True
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break

                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue

                st, path, threat, err = self.parse_clamscan_line(line)
                if st:
                    scanned += 1
                    target_display = path or (file_paths[min(scanned - 1, total - 1)])
                    if progress_callback:
                        progress_callback(scanned, total, target_display)

                    if st == "FOUND":
                        summary.scanned_files += 1
                        summary.infected_files += 1
                        det = ScanDetection(file_path=target_display, threat_name=threat or "Threat")
                        summary.detections.append(det)
                        if detection_callback:
                            detection_callback(det)
                    elif st == "OK":
                        summary.scanned_files += 1
                    elif st == "ERROR":
                        summary.error_files += 1

            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.communicate(timeout=2)
                except Exception:
                    pass
        except Exception as exc:
            logger.error(f"Batch scan failed: {exc}")
        finally:
            self._active_proc = None
            if temp_list and os.path.exists(temp_list):
                try:
                    os.remove(temp_list)
                except Exception:
                    pass

        return summary
