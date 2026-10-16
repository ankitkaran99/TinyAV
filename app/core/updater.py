import os
import re
import subprocess
import threading
from datetime import datetime
from typing import Callable, Optional, Tuple

from apscheduler.schedulers.background import BackgroundScheduler
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger

logger = get_logger()

VERSION_REGEX = re.compile(r"version:\s*(\d+)", re.IGNORECASE)
DAILY_REGEX = re.compile(r"daily(?:\.(?:cld|cvd))?.*?version:\s*(\d+)", re.IGNORECASE)
MAIN_REGEX = re.compile(r"main(?:\.(?:cld|cvd))?.*?version:\s*(\d+)", re.IGNORECASE)
BYTECODE_REGEX = re.compile(r"bytecode(?:\.(?:cld|cvd))?.*?version:\s*(\d+)", re.IGNORECASE)

class UpdateManager:
    def __init__(self, config_manager: ConfigManager, engine: ClamAVEngine):
        self.config_manager = config_manager
        self.engine = engine
        self.scheduler: Optional[BackgroundScheduler] = None
        self.is_updating = False
        self._lock = threading.Lock()
        self.on_update_status_change: Optional[Callable[[str, bool, Optional[str]], None]] = None

    def start_scheduler(self) -> None:
        if self.scheduler and self.scheduler.running:
            return

        self.scheduler = BackgroundScheduler(daemon=True)
        interval = max(1, self.config_manager.config.update_interval_hours)
        if self.config_manager.config.auto_update_enabled:
            self.scheduler.add_job(
                self._scheduled_update_job,
                "interval",
                hours=interval,
                id="clamav_freshclam_job",
                replace_existing=True,
            )
        self.scheduler.start()
        logger.info(f"Update scheduler started (interval: {interval}h, enabled: {self.config_manager.config.auto_update_enabled})")

    def reschedule(self, interval_hours: int, enabled: bool) -> None:
        if not self.scheduler:
            self.start_scheduler()
            return

        job = self.scheduler.get_job("clamav_freshclam_job")
        if not enabled:
            if job:
                self.scheduler.remove_job("clamav_freshclam_job")
                logger.info("Automatic updates disabled.")
            return

        interval = max(1, interval_hours)
        if job:
            self.scheduler.reschedule_job(
                "clamav_freshclam_job",
                trigger="interval",
                hours=interval,
            )
            logger.info(f"Rescheduled update job to every {interval}h")
        else:
            self.scheduler.add_job(
                self._scheduled_update_job,
                "interval",
                hours=interval,
                id="clamav_freshclam_job",
                replace_existing=True,
            )
            logger.info(f"Added update job with interval {interval}h")

    def stop_scheduler(self) -> None:
        if self.scheduler and self.scheduler.running:
            try:
                self.scheduler.shutdown(wait=False)
                logger.info("Update scheduler stopped.")
            except Exception as exc:
                logger.warning(f"Error stopping scheduler: {exc}")

    def _scheduled_update_job(self) -> None:
        logger.info("Running scheduled ClamAV virus definition update...")
        self.run_update(is_scheduled=True)

    def run_update_async(
        self,
        is_scheduled: bool = False,
        callback: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        threading.Thread(
            target=lambda: self._run_update_wrapper(is_scheduled, callback),
            daemon=True,
            name="TinyAV-Updater",
        ).start()

    def _run_update_wrapper(
        self,
        is_scheduled: bool,
        callback: Optional[Callable[[bool, str], None]],
    ) -> None:
        success, message = self.run_update(is_scheduled=is_scheduled)
        if callback:
            callback(success, message)

    def parse_definition_version(self, freshclam_output: str) -> str:
        """
        Extracts accurate ClamAV database definition versions from freshclam output.
        Correctly distinguishes between daily, main, and bytecode databases to prevent
        the static bytecode version (e.g. 339) from overshadowing the daily version (e.g. 28155).
        """
        daily_match = DAILY_REGEX.search(freshclam_output)
        main_match = MAIN_REGEX.search(freshclam_output)
        bytecode_match = BYTECODE_REGEX.search(freshclam_output)

        daily_ver = daily_match.group(1) if daily_match else None
        main_ver = main_match.group(1) if main_match else None
        byte_ver = bytecode_match.group(1) if bytecode_match else None

        # Fallback to engine version (e.g. ClamAV 1.5.4/28155/...) if daily was not in output
        if not daily_ver and hasattr(self, "engine") and self.engine and self.engine.engine_version:
            m_eng = re.search(r"/\s*(\d{4,6})\s*/", self.engine.engine_version)
            if m_eng:
                daily_ver = m_eng.group(1)

        # Fallback to highest numeric version from general version regex (daily is 28000+)
        if not daily_ver:
            versions = VERSION_REGEX.findall(freshclam_output)
            if versions:
                int_versions = [int(v) for v in versions if v.isdigit()]
                if int_versions:
                    daily_ver = str(max(int_versions))

        if daily_ver:
            return f"Daily ver. {daily_ver}"

        return "Up to date"

    def run_update(self, is_scheduled: bool = False) -> Tuple[bool, str]:
        with self._lock:
            if self.is_updating:
                return False, "An update is already in progress."
            self.is_updating = True

        if self.on_update_status_change:
            self.on_update_status_change("Starting update...", True, None)

        freshclam_bin = self.engine.find_binary("freshclam")
        if not freshclam_bin:
            from app.core.config_generator import ClamAVConfigGenerator
            detected = ClamAVConfigGenerator.detect_clamav_dir(self.config_manager, self.engine)
            if detected:
                msg = (
                    f"freshclam executable not found in configured path, but ClamAV was detected at:\n{detected}\n"
                    "Tip: Click 'Auto-Generate Conf Files' to configure TinyAV and generate settings."
                )
            else:
                msg = "freshclam executable not found. Please install ClamAV or configure its bin directory in Settings."
            logger.error(msg)
            with self._lock:
                self.is_updating = False
            if self.on_update_status_change:
                self.on_update_status_change("freshclam not found", False, msg)
            return False, msg

        try:
            cmd = [freshclam_bin]
            conf_file = os.path.join(os.path.dirname(freshclam_bin), "freshclam.conf")
            if os.path.isfile(conf_file):
                cmd.append(f"--config-file={conf_file}")

            logger.info(f"Executing freshclam: {' '.join(cmd)}")
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=os.path.dirname(freshclam_bin),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                timeout=300,
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            full_out = f"{stdout}\n{stderr}".strip()

            # freshclam exit code: 0 = databases updated or up to date, 1 = error, 2 = config error
            success = proc.returncode == 0

            # Extract accurate daily database version from output
            latest_version = self.parse_definition_version(full_out)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if success:
                self.config_manager.update(
                    last_update_time=timestamp,
                    definition_version=latest_version,
                )
                msg = f"Update succeeded at {timestamp}. {latest_version}"
                logger.info(msg)
                # Tell engine to refresh / tell clamd to reload if available
                if self.engine.clamd_client:
                    try:
                        self.engine.clamd_client.reload()
                        logger.info("Notified clamd to reload definition databases.")
                    except Exception as e:
                        logger.debug(f"clamd reload error: {e}")
                self.engine.refresh_engine()
            else:
                err_text = stderr or stdout or "Update failed"
                if proc.returncode == 2 or "config file" in err_text.lower():
                    msg = (
                        f"freshclam returned code {proc.returncode}: {err_text}\n"
                        "Tip: ClamAV configuration files are missing or incomplete. "
                        "Click 'Auto-Generate Conf Files' to generate optimized freshclam.conf and clamd.conf automatically."
                    )
                else:
                    msg = f"freshclam returned code {proc.returncode}: {err_text}"
                logger.warning(msg)

            with self._lock:
                self.is_updating = False

            if self.on_update_status_change:
                self.on_update_status_change("Idle", False, msg if not success else None)

            return success, msg
        except subprocess.TimeoutExpired:
            msg = "Update timed out after 5 minutes."
            logger.error(msg)
            with self._lock:
                self.is_updating = False
            if self.on_update_status_change:
                self.on_update_status_change("Idle", False, msg)
            return False, msg
        except Exception as exc:
            msg = f"Update error: {exc}"
            logger.error(msg)
            with self._lock:
                self.is_updating = False
            if self.on_update_status_change:
                self.on_update_status_change("Idle", False, msg)
            return False, msg
