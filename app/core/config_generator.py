import os
import sys
from typing import List, Optional, Tuple

import win32api
import win32con
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine
from app.core.logger import get_logger

logger = get_logger()

FRESHCLAM_TEMPLATE = """# Auto-generated and optimized by TinyAV
# Database directory must match clamd.conf
DatabaseDirectory "{database_dir}"

# CVD Certs Directory (if present)
{certs_directive}

# Logging configuration
UpdateLogFile "{freshclam_log}"
LogTime yes
LogFileMaxSize 2M
LogRotate yes

# Mirror and Network Settings
DatabaseMirror database.clamav.net
MaxAttempts 3
ConnectTimeout 30
ReceiveTimeout 60
ScriptedUpdates yes
CompressLocalDatabase no
Checks 12
DNSDatabaseInfo current.cvd.clamav.net
"""

CLAMD_TEMPLATE = """# Auto-generated and optimized by TinyAV
# Database directory must match freshclam.conf
DatabaseDirectory "{database_dir}"

# CVD Certs Directory (if present)
{certs_directive}

# Daemon Logging
LogFile "{clamd_log}"
LogTime yes
LogFileMaxSize 2M
LogRotate yes

# Network Socket for TinyAV IPC
TCPSocket 3310
TCPAddr 127.0.0.1

# Performance and Resource Limits
MaxConnectionQueueLength 30
MaxThreads 10
StreamMaxLength 100M
MaxFileSize 100M
MaxScanSize 400M
MaxRecursion 16
PCREMaxFileSize 100M
"""


class ClamAVConfigGenerator:
    """Helper to detect ClamAV installation and generate optimized freshclam.conf and clamd.conf."""

    @staticmethod
    def detect_clamav_dir(config_manager: Optional[ConfigManager] = None, engine: Optional[ClamAVEngine] = None) -> Optional[str]:
        """Detect the root directory of the ClamAV installation."""
        if config_manager and config_manager.config.clamav_bin_dir:
            if os.path.isdir(config_manager.config.clamav_bin_dir):
                return os.path.normpath(config_manager.config.clamav_bin_dir)

        if engine:
            for b in ("freshclam", "clamscan", "clamd"):
                bin_path = engine.find_binary(b)
                if bin_path:
                    return os.path.normpath(os.path.dirname(bin_path))

        common_dirs = [
            r"C:\tools\clamav",
            r"C:\Program Files\ClamAV",
            r"C:\Program Files (x86)\ClamAV",
            r"C:\ClamAV",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\ClamAV"),
            os.path.expandvars(r"%USERPROFILE%\scoop\apps\clamav\current"),
        ]
        for d in common_dirs:
            if os.path.isdir(d):
                return os.path.normpath(d)

        return None

    @classmethod
    def generate_configs_direct(cls, clamav_dir: str, overwrite: bool = True) -> Tuple[bool, str, List[str]]:
        """
        Generates freshclam.conf and clamd.conf in the specified ClamAV directory.
        Creates the database directory if it does not already exist.
        If overwrite is False, existing freshclam.conf and clamd.conf are preserved.
        """
        if not clamav_dir or not os.path.isdir(clamav_dir):
            return False, f"Directory does not exist: {clamav_dir}", []

        clamav_dir = os.path.normpath(clamav_dir)
        db_dir = os.path.join(clamav_dir, "database")
        certs_dir = os.path.join(clamav_dir, "certs")
        freshclam_conf_path = os.path.join(clamav_dir, "freshclam.conf")
        clamd_conf_path = os.path.join(clamav_dir, "clamd.conf")

        freshclam_log = os.path.join(clamav_dir, "freshclam.log")
        clamd_log = os.path.join(clamav_dir, "clamd.log")

        created_files = []

        try:
            # 1. Ensure database directory exists
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created ClamAV database directory: {db_dir}")

            certs_directive = f'CVDCertsDirectory "{certs_dir}"' if os.path.isdir(certs_dir) else "# CVDCertsDirectory certs"

            # 2. Write freshclam.conf
            if overwrite or not os.path.isfile(freshclam_conf_path):
                freshclam_content = FRESHCLAM_TEMPLATE.format(
                    database_dir=db_dir,
                    certs_directive=certs_directive,
                    freshclam_log=freshclam_log,
                )
                with open(freshclam_conf_path, "w", encoding="utf-8") as f:
                    f.write(freshclam_content)
                created_files.append(freshclam_conf_path)
                logger.info(f"Generated freshclam.conf at {freshclam_conf_path}")
            else:
                logger.info(f"Preserving existing freshclam.conf at {freshclam_conf_path}")

            # 3. Write clamd.conf
            if overwrite or not os.path.isfile(clamd_conf_path):
                clamd_content = CLAMD_TEMPLATE.format(
                    database_dir=db_dir,
                    certs_directive=certs_directive,
                    clamd_log=clamd_log,
                )
                with open(clamd_conf_path, "w", encoding="utf-8") as f:
                    f.write(clamd_content)
                created_files.append(clamd_conf_path)
                logger.info(f"Generated clamd.conf at {clamd_conf_path}")
            else:
                logger.info(f"Preserving existing clamd.conf at {clamd_conf_path}")

            msg = (
                f"Successfully generated optimized ClamAV configurations in:\n{clamav_dir}\n"
                f"- Configured database directory: {db_dir}\n"
                f"- Created freshclam.conf\n"
                f"- Created clamd.conf (TCP 127.0.0.1:3310)"
            )
            return True, msg, created_files

        except PermissionError as exc:
            logger.warning(f"Permission denied writing configs to {clamav_dir}: {exc}")
            raise
        except Exception as exc:
            logger.error(f"Failed to generate ClamAV configs: {exc}")
            return False, f"Failed to generate configs: {exc}", created_files

    @classmethod
    def generate_configs_elevated(cls, clamav_dir: str) -> Tuple[bool, str, List[str]]:
        """Launches TinyAV with administrator privileges via UAC to generate configs."""
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        main_py = os.path.join(project_root, "main.py")

        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = f'--generate-clamav-config "{clamav_dir}"'
        else:
            exe = sys.executable
            params = f'"{main_py}" --generate-clamav-config "{clamav_dir}"'

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
                msg = f"Requested administrator elevation to write configs to: {clamav_dir}"
                return True, msg, []
            else:
                return False, f"Elevation failed with code: {ret}", []
        except Exception as exc:
            return False, f"UAC prompt cancelled or failed: {exc}", []

    @classmethod
    def generate_configs(
        cls,
        clamav_dir: str = "",
        config_manager: Optional[ConfigManager] = None,
        engine: Optional[ClamAVEngine] = None,
    ) -> Tuple[bool, str, List[str]]:
        """
        High-level method to detect directory (if empty), generate configs directly,
        or escalate via UAC if permission denied. Also updates config_manager and engine.
        """
        target_dir = clamav_dir.strip() if clamav_dir else ""
        if not target_dir:
            target_dir = cls.detect_clamav_dir(config_manager=config_manager, engine=engine) or ""

        if not target_dir:
            return False, "Could not locate ClamAV installation directory. Please specify it in Settings.", []

        try:
            success, msg, files = cls.generate_configs_direct(target_dir)
        except PermissionError:
            # Need Administrator elevation
            logger.info(f"Elevating permissions to configure ClamAV at {target_dir}")
            return cls.generate_configs_elevated(target_dir)

        if success:
            if config_manager and config_manager.config.clamav_bin_dir != target_dir:
                config_manager.update(clamav_bin_dir=target_dir)
            if engine:
                engine.refresh_engine()

        return success, msg, files
