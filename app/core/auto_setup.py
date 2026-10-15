import os
import shutil
import sys
import threading
from typing import Callable, Optional, Tuple

from app.core.binary_updater import ClamAVBinaryUpdater, ReleaseAsset
from app.core.config import ConfigManager
from app.core.config_generator import ClamAVConfigGenerator
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger
from app.platform_win.service_manager import ClamDServiceManager, wait_for_clamd_socket

logger = get_logger()


class AutoProvisioner:
    """
    Automated zero-config bootstrap for ClamAV.
    Downloads, extracts, configures, and initializes ClamAV and virus definitions
    so novice users can use TinyAV out-of-the-box with 1-click.
    """

    def __init__(self, config_manager: ConfigManager, engine: ClamAVEngine):
        self.config_manager = config_manager
        self.engine = engine
        self.binary_updater = ClamAVBinaryUpdater(config_manager, engine)
        self._is_running = False
        self._lock = threading.Lock()

    @classmethod
    def is_setup_needed(cls, engine: ClamAVEngine) -> bool:
        """Returns True if no ClamAV engine binary is installed or detected."""
        return not engine.is_available()

    @classmethod
    def get_default_install_dir(cls) -> str:
        """
        Returns standard user-accessible installation directory.
        No administrator privileges required for downloading or updating definitions here.
        """
        local_appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.normpath(os.path.join(local_appdata, "Programs", "ClamAV"))

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def run_provisioning_async(
        self,
        target_dir: Optional[str] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        """Executes the complete out-of-the-box setup in a background worker thread."""
        with self._lock:
            if self._is_running:
                if completion_callback:
                    completion_callback(False, "Setup is already in progress.")
                return
            self._is_running = True

        dest_dir = target_dir or self.get_default_install_dir()

        def worker():
            try:
                success, msg = self._do_provisioning(dest_dir, progress_callback)
            except Exception as exc:
                logger.error(f"Auto-provisioning failed: {exc}", exc_info=True)
                success, msg = False, f"Unexpected error during setup: {exc}"
            finally:
                with self._lock:
                    self._is_running = False

            if completion_callback:
                completion_callback(success, msg)

        threading.Thread(target=worker, daemon=True, name="TinyAV-AutoProvisioner").start()

    def _do_provisioning(
        self,
        target_dir: str,
        progress_cb: Optional[Callable[[str, float], None]] = None,
    ) -> Tuple[bool, str]:
        def report(status: str, pct: float):
            logger.info(f"AutoProvision: {status} ({pct:.1f}%)")
            if progress_cb:
                progress_cb(status, pct)

        os.makedirs(target_dir, exist_ok=True)

        # Step 1: Query latest ClamAV engine release from GitHub
        report("Checking latest ClamAV release...", 5.0)
        ok, msg, release_info = self.binary_updater.check_for_updates()
        if not ok or not release_info or not release_info.zip_asset:
            return False, f"Could not find compatible ClamAV release for your system: {msg}"

        asset: ReleaseAsset = release_info.zip_asset
        temp_zip = os.path.join(
            os.environ.get("TEMP", os.path.expanduser("~")),
            f"tinyav_clamav_setup_{asset.name}",
        )

        # Step 2: Download ClamAV portable zip
        report(f"Downloading ClamAV engine {release_info.version}...", 10.0)

        def dl_progress(down: int, total: int, pct: float):
            mb_down = down / (1024 * 1024)
            mb_tot = total / (1024 * 1024)
            # Map download progress between 10% and 55%
            mapped_pct = 10.0 + (pct * 0.45)
            report(f"Downloading ClamAV engine ({mb_down:.1f} MB / {mb_tot:.1f} MB)...", mapped_pct)

        ok, msg = self.binary_updater.download_file(
            url=asset.download_url,
            dest_path=temp_zip,
            expected_size=asset.size,
            progress_callback=dl_progress,
        )
        if not ok:
            return False, f"Download failed: {msg}"

        # Step 3: Extract portable ZIP into target_dir
        report("Extracting ClamAV binaries...", 60.0)
        try:
            ok, msg, count = ClamAVBinaryUpdater.apply_zip_update_direct(temp_zip, target_dir)
            if not ok:
                return False, f"Extraction failed: {msg}"
        finally:
            try:
                if os.path.isfile(temp_zip):
                    os.remove(temp_zip)
            except Exception:
                pass

        # Step 4: Generate optimized clamd.conf and freshclam.conf
        report("Configuring ClamAV Daemon & Database settings...", 70.0)
        ok, msg, files = ClamAVConfigGenerator.generate_configs_direct(target_dir, overwrite=False)
        if not ok:
            return False, f"Configuration setup failed: {msg}"

        # Step 5: Update TinyAV config to use the new directory
        report("Saving TinyAV configuration...", 75.0)
        self.config_manager.update(
            clamav_bin_dir=target_dir,
            prefer_clamd=True,
        )
        self.engine.refresh_engine()

        # Step 6: Download initial virus definitions with freshclam if database is empty
        db_dir = os.path.join(target_dir, "database")
        has_db = False
        if os.path.isdir(db_dir):
            has_db = any(f.endswith((".cvd", ".cld")) for f in os.listdir(db_dir))

        if not has_db:
            report("Fetching initial virus definition database (freshclam)...", 80.0)
            freshclam_exe = os.path.join(target_dir, "freshclam.exe")
            freshclam_conf = os.path.join(target_dir, "freshclam.conf")
            if os.path.isfile(freshclam_exe):
                try:
                    cmd = [freshclam_exe]
                    if os.path.isfile(freshclam_conf):
                        cmd.extend(["--config-file", freshclam_conf])
                    import subprocess
                    subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                except Exception as exc:
                    logger.warning(f"Initial freshclam run notice: {exc}")

        # Step 7: Install and Start clamd Windows Service
        report("Setting up background ClamD service...", 90.0)
        try:
            ClamDServiceManager.install_service_elevated(target_dir)
            wait_for_clamd_socket(
                host=self.config_manager.config.clamd_host,
                port=self.config_manager.config.clamd_port,
                timeout=20.0,
            )
        except Exception as exc:
            logger.debug(f"Service setup notice: {exc}")

        # Finalize
        self.engine.refresh_engine()
        report("Setup complete! TinyAV is ready and active.", 100.0)
        return True, f"ClamAV {release_info.version} installed and configured successfully in {target_dir}!"
