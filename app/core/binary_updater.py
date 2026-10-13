import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import win32api
import win32con
from app.core.config import ConfigManager
from app.core.config_generator import ClamAVConfigGenerator
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger

logger = get_logger()

GITHUB_API_LATEST = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"
GITHUB_RELEASES_PAGE = "https://github.com/Cisco-Talos/clamav/releases"


def get_system_arch() -> str:
    """Returns 'x64', 'arm64', or 'win32' matching ClamAV release assets."""
    m = platform.machine().lower()
    if "arm" in m or "aarch64" in m:
        return "arm64"
    elif sys.maxsize > 2**32:
        return "x64"
    else:
        return "win32"


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Extracts numeric version tuple from strings like 'clamav-1.5.4' or '1.5.4'."""
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", v_str)
    if not match:
        return (0, 0, 0)
    return tuple(int(x) for x in match.groups() if x is not None)


@dataclass
class ReleaseAsset:
    name: str
    size: int
    download_url: str
    content_type: str


@dataclass
class ClamAVReleaseInfo:
    tag_name: str
    version: str
    release_name: str
    html_url: str
    published_at: str
    zip_asset: Optional[ReleaseAsset] = None
    msi_asset: Optional[ReleaseAsset] = None
    is_newer: bool = False
    current_version: str = "Unknown"


class ClamAVBinaryUpdater:
    """Manages checking and updating ClamAV binaries from Cisco-Talos/clamav GitHub releases."""

    def __init__(self, config_manager: ConfigManager, engine: ClamAVEngine):
        self.config_manager = config_manager
        self.engine = engine
        self._is_busy = False
        self._cancel_flag = threading.Event()
        self._lock = threading.Lock()

    @property
    def is_busy(self) -> bool:
        return self._is_busy

    def cancel(self) -> None:
        self._cancel_flag.set()

    def check_for_updates(self) -> Tuple[bool, str, Optional[ClamAVReleaseInfo]]:
        """
        Queries the GitHub Releases API to check the latest ClamAV release.
        Compares with the installed engine version.
        """
        try:
            req = urllib.request.Request(
                GITHUB_API_LATEST,
                headers={
                    "User-Agent": "TinyAV-Windows-Client",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                import json
                data = json.loads(response.read().decode("utf-8"))

            tag_name = data.get("tag_name", "")
            release_name = data.get("name", tag_name)
            html_url = data.get("html_url", GITHUB_RELEASES_PAGE)
            published_at = data.get("published_at", "")

            # Version string cleanup
            version_match = re.search(r"(\d+\.\d+\.\d+)", tag_name)
            latest_version_str = version_match.group(1) if version_match else tag_name.replace("clamav-", "")

            arch = get_system_arch()
            zip_asset: Optional[ReleaseAsset] = None
            msi_asset: Optional[ReleaseAsset] = None

            for asset in data.get("assets", []):
                name = asset.get("name", "")
                size = asset.get("size", 0)
                url = asset.get("browser_download_url", "")
                ctype = asset.get("content_type", "")

                # Exclude .sig signature files
                if name.endswith(".sig"):
                    continue

                if f".win.{arch}.zip" in name.lower():
                    zip_asset = ReleaseAsset(name=name, size=size, download_url=url, content_type=ctype)
                elif f".win.{arch}.msi" in name.lower():
                    msi_asset = ReleaseAsset(name=name, size=size, download_url=url, content_type=ctype)

            # Determine currently installed version
            current_ver_str = "Not Installed"
            if self.engine.clamscan_path or self.engine.clamd_path:
                cur_match = re.search(r"(\d+\.\d+\.\d+)", self.engine.engine_version)
                if cur_match:
                    current_ver_str = cur_match.group(1)
                else:
                    current_ver_str = self.engine.engine_version

            cur_tuple = parse_version_tuple(current_ver_str)
            latest_tuple = parse_version_tuple(latest_version_str)
            is_newer = latest_tuple > cur_tuple

            info = ClamAVReleaseInfo(
                tag_name=tag_name,
                version=latest_version_str,
                release_name=release_name,
                html_url=html_url,
                published_at=published_at,
                zip_asset=zip_asset,
                msi_asset=msi_asset,
                is_newer=is_newer,
                current_version=current_ver_str,
            )

            status_msg = (
                f"New update available: ClamAV {latest_version_str} (Installed: {current_ver_str})"
                if is_newer
                else f"ClamAV is up to date (Version {latest_version_str})"
            )
            return True, status_msg, info

        except urllib.error.URLError as exc:
            msg = f"Network error checking ClamAV releases: {exc.reason}"
            logger.warning(msg)
            return False, msg, None
        except Exception as exc:
            msg = f"Failed to check ClamAV release: {exc}"
            logger.warning(msg)
            return False, msg, None

    def download_file(
        self,
        url: str,
        dest_path: str,
        expected_size: int = 0,
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
    ) -> Tuple[bool, str]:
        """
        Streams a download from url to dest_path with progress updates and cancellation.
        progress_callback receives (downloaded_bytes, total_bytes, percentage).
        """
        self._cancel_flag.clear()
        try:
            os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "TinyAV-Windows-Client"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                total_size = int(resp.headers.get("content-length", expected_size))
                downloaded = 0
                chunk_size = 64 * 1024  # 64 KB chunks

                with open(dest_path, "wb") as f:
                    while True:
                        if self._cancel_flag.is_set():
                            return False, "Download cancelled by user."
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback:
                            percent = (downloaded / total_size * 100.0) if total_size > 0 else 0.0
                            progress_callback(downloaded, total_size, percent)

            if total_size > 0 and downloaded < total_size:
                return False, f"Incomplete download ({downloaded} of {total_size} bytes)"

            return True, "Download completed successfully."

        except Exception as exc:
            logger.error(f"Download failed for {url}: {exc}")
            return False, f"Download error: {exc}"

    @classmethod
    def apply_zip_update_direct(cls, zip_path: str, target_dir: str) -> Tuple[bool, str, int]:
        """
        Extracts ClamAV portable zip archive into target_dir.
        Preserves existing configuration files (freshclam.conf, clamd.conf) and the database folder.
        """
        if not os.path.isfile(zip_path):
            return False, f"ZIP file not found: {zip_path}", 0
        if not target_dir:
            return False, "Target ClamAV directory is unspecified.", 0

        target_dir = os.path.normpath(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        extracted_count = 0
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Find common top-level prefix if present (e.g. 'clamav-1.5.4.win.x64/')
                namelist = zf.namelist()
                top_dirs = set(n.split("/")[0] for n in namelist if "/" in n)
                prefix = ""
                if len(top_dirs) == 1:
                    prefix = list(top_dirs)[0] + "/"

                for member in zf.infolist():
                    rel_name = member.filename
                    if prefix and rel_name.startswith(prefix):
                        rel_name = rel_name[len(prefix):]

                    if not rel_name:
                        continue

                    # Prevent path traversal vulnerabilities
                    dest_file = os.path.normpath(os.path.join(target_dir, rel_name))
                    if not dest_file.startswith(target_dir):
                        continue

                    if member.is_dir():
                        os.makedirs(dest_file, exist_ok=True)
                        continue

                    # Preserve existing custom configuration and database
                    lower_rel = rel_name.lower().replace("\\", "/")
                    if os.path.exists(dest_file):
                        if lower_rel in ("freshclam.conf", "clamd.conf") or lower_rel.startswith("database/"):
                            logger.info(f"Preserving existing user file: {rel_name}")
                            continue

                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    with zf.open(member) as source, open(dest_file, "wb") as target:
                        shutil.copyfileobj(source, target)
                    extracted_count += 1

            # Ensure optimized configuration exists in destination if not already present
            ClamAVConfigGenerator.generate_configs_direct(target_dir, overwrite=False)

            msg = f"Successfully extracted and updated {extracted_count} ClamAV files into {target_dir}."
            logger.info(msg)
            return True, msg, extracted_count

        except PermissionError as exc:
            logger.warning(f"Permission denied extracting ClamAV files to {target_dir}: {exc}")
            raise
        except Exception as exc:
            logger.error(f"Failed extracting ClamAV zip: {exc}")
            return False, f"Extraction failed: {exc}", extracted_count

    @classmethod
    def apply_zip_update_elevated(cls, zip_path: str, target_dir: str) -> Tuple[bool, str]:
        """Elevates via UAC to extract files into protected directories like Program Files."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        main_py = os.path.join(project_root, "main.py")

        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = f'--apply-clamav-zip "{zip_path}" "{target_dir}"'
        else:
            exe = sys.executable
            params = f'"{main_py}" --apply-clamav-zip "{zip_path}" "{target_dir}"'

        try:
            ret = win32api.ShellExecute(
                0,
                "runas",
                exe,
                params,
                None,
                win32con.SW_NORMAL,
            )
            if ret > 32:
                return True, f"Requested administrator elevation to update ClamAV in: {target_dir}"
            else:
                return False, f"Failed to elevate process (error code {ret})"
        except Exception as exc:
            return False, f"UAC prompt cancelled or failed: {exc}"

    def update_portable_binaries_async(
        self,
        asset: ReleaseAsset,
        target_dir: str,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        """Downloads and applies the portable ZIP release in a background thread."""
        with self._lock:
            if self._is_busy:
                if completion_callback:
                    completion_callback(False, "An update or download is already running.")
                return
            self._is_busy = True

        def worker():
            temp_zip = os.path.join(
                os.environ.get("TEMP", os.path.expanduser("~")),
                f"tinyav_clamav_update_{asset.name}",
            )
            try:
                if progress_callback:
                    progress_callback("Connecting to GitHub...", 0.0)

                def dl_progress(down: int, total: int, pct: float):
                    if progress_callback:
                        mb_down = down / (1024 * 1024)
                        mb_tot = total / (1024 * 1024)
                        msg = f"Downloading ClamAV ({mb_down:.1f} MB of {mb_tot:.1f} MB)..."
                        progress_callback(msg, pct)

                ok, msg = self.download_file(
                    url=asset.download_url,
                    dest_path=temp_zip,
                    expected_size=asset.size,
                    progress_callback=dl_progress,
                )
                if not ok:
                    with self._lock:
                        self._is_busy = False
                    if completion_callback:
                        completion_callback(False, msg)
                    return

                if progress_callback:
                    progress_callback("Extracting and installing binaries...", 95.0)

                try:
                    success, res_msg, count = self.apply_zip_update_direct(temp_zip, target_dir)
                except PermissionError:
                    if progress_callback:
                        progress_callback("Requesting administrator elevation...", 98.0)
                    success, res_msg = self.apply_zip_update_elevated(temp_zip, target_dir)

                if success:
                    # Update configuration and refresh engine
                    self.config_manager.update(clamav_bin_dir=target_dir)
                    self.engine.refresh_engine()

                with self._lock:
                    self._is_busy = False

                if completion_callback:
                    completion_callback(success, res_msg)

            except Exception as exc:
                with self._lock:
                    self._is_busy = False
                logger.error(f"Error in ClamAV binary update worker: {exc}")
                if completion_callback:
                    completion_callback(False, f"Update failed: {exc}")
            finally:
                # Clean up temp file if not elevated
                if os.path.isfile(temp_zip) and not self._is_busy:
                    try:
                        os.remove(temp_zip)
                    except Exception:
                        pass

        threading.Thread(target=worker, daemon=True, name="ClamAV-BinaryUpdater").start()

    def download_and_run_msi_async(
        self,
        asset: ReleaseAsset,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        completion_callback: Optional[Callable[[bool, str], None]] = None,
    ) -> None:
        """Downloads the official MSI installer and executes it."""
        with self._lock:
            if self._is_busy:
                if completion_callback:
                    completion_callback(False, "An update or download is already running.")
                return
            self._is_busy = True

        def worker():
            user_downloads = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Downloads")
            dest_msi = os.path.join(user_downloads, asset.name)
            try:
                def dl_progress(down: int, total: int, pct: float):
                    if progress_callback:
                        mb_down = down / (1024 * 1024)
                        mb_tot = total / (1024 * 1024)
                        msg = f"Downloading installer ({mb_down:.1f} MB of {mb_tot:.1f} MB)..."
                        progress_callback(msg, pct)

                ok, msg = self.download_file(
                    url=asset.download_url,
                    dest_path=dest_msi,
                    expected_size=asset.size,
                    progress_callback=dl_progress,
                )
                if not ok:
                    with self._lock:
                        self._is_busy = False
                    if completion_callback:
                        completion_callback(False, msg)
                    return

                if progress_callback:
                    progress_callback("Launching Windows Installer...", 100.0)

                # Launch MSI installer via msiexec
                subprocess.Popen(["msiexec.exe", "/i", dest_msi])
                success_msg = f"Downloaded {asset.name} to Downloads folder and launched Windows installer."

                with self._lock:
                    self._is_busy = False

                if completion_callback:
                    completion_callback(True, success_msg)

            except Exception as exc:
                with self._lock:
                    self._is_busy = False
                logger.error(f"Error launching MSI installer: {exc}")
                if completion_callback:
                    completion_callback(False, f"Installer error: {exc}")

        threading.Thread(target=worker, daemon=True, name="ClamAV-MsiUpdater").start()
