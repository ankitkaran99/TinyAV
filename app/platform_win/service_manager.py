import ctypes
import os
import subprocess
import sys
import time
from typing import Optional, Tuple

import win32api
import win32con
from app.core.config_generator import ClamAVConfigGenerator
from app.core.logger import get_logger

logger = get_logger()

SERVICE_NAME = "clamd"
DISPLAY_NAME = "ClamAV ClamD Service"
DESCRIPTION = "ClamAV ClamD Background Antivirus Daemon for TinyAV"


def is_admin() -> bool:
    """Returns True if the current process is running with administrative privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_clamd_service_status(service_name: str = SERVICE_NAME) -> str:
    """
    Returns the current status of the clamd Windows Service:
      - 'RUNNING'
      - 'STOPPED'
      - 'START_PENDING'
      - 'STOP_PENDING'
      - 'PAUSED'
      - 'NOT_INSTALLED'
      - 'UNKNOWN'
    """
    try:
        import pywintypes
        import win32service
        import win32serviceutil

        try:
            status = win32serviceutil.QueryServiceStatus(service_name)
            state = status[1]
            if state == win32service.SERVICE_RUNNING:
                return "RUNNING"
            elif state == win32service.SERVICE_STOPPED:
                return "STOPPED"
            elif state == win32service.SERVICE_START_PENDING:
                return "START_PENDING"
            elif state == win32service.SERVICE_STOP_PENDING:
                return "STOP_PENDING"
            elif state == win32service.SERVICE_PAUSED:
                return "PAUSED"
            return f"STATE_{state}"
        except pywintypes.error as e:
            if e.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return "NOT_INSTALLED"
            logger.debug(f"win32service error querying {service_name}: {e}")
    except Exception as exc:
        logger.debug(f"win32serviceutil not available or failed: {exc}")

    # Fallback to sc.exe query
    try:
        res = subprocess.run(["sc.exe", "query", service_name], capture_output=True, text=True, timeout=5)
        out = (res.stdout + res.stderr).upper()
        if "1060" in out or "DOES NOT EXIST" in out:
            return "NOT_INSTALLED"
        if "STATE" in out:
            if "RUNNING" in out:
                return "RUNNING"
            if "STOPPED" in out:
                return "STOPPED"
            if "START_PENDING" in out:
                return "START_PENDING"
            if "STOP_PENDING" in out:
                return "STOP_PENDING"
    except Exception as exc:
        logger.debug(f"sc.exe query failed: {exc}")

    return "UNKNOWN"


def is_clamd_service_installed() -> bool:
    """Checks if clamd service is registered in Windows."""
    return get_clamd_service_status() != "NOT_INSTALLED"


def is_clamd_service_running() -> bool:
    """Checks if clamd service is currently in RUNNING state."""
    return get_clamd_service_status() == "RUNNING"


def wait_for_clamd_socket(host: str = "127.0.0.1", port: int = 3310, timeout: float = 15.0) -> bool:
    """
    Polls the clamd socket until it responds with PONG or timeout expires.
    Gives daemon time to load signature databases into memory.
    """
    import clamd

    start = time.time()
    while time.time() - start < timeout:
        try:
            client = clamd.ClamdNetworkSocket(host=host, port=port, timeout=1.5)
            if client.ping() == "PONG":
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _elevate_command(param_str: str) -> Tuple[bool, str]:
    """Helper to launch main.py with elevated administrative rights via UAC."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_py = os.path.join(project_root, "main.py")

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = param_str
    else:
        exe = sys.executable
        params = f'"{main_py}" {param_str}'

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
            return True, "Administrator elevation requested. Service operation is executing..."
        else:
            return False, f"Elevation failed with code: {ret}"
    except Exception as exc:
        return False, f"UAC prompt cancelled or failed: {exc}"


class ClamDServiceManager:
    """Manager for installation, control, and status monitoring of clamd Windows Service."""

    @classmethod
    def get_service_status(cls) -> str:
        return get_clamd_service_status(SERVICE_NAME)

    @classmethod
    def is_installed(cls) -> bool:
        return is_clamd_service_installed()

    @classmethod
    def is_running(cls) -> bool:
        return is_clamd_service_running()

    @classmethod
    def install_service_direct(cls, clamav_dir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Directly installs and starts the clamd Windows Service (must be elevated).
        1. Resolves ClamAV directory and clamd.exe.
        2. Generates/validates clamd.conf and database folder.
        3. Removes existing clamd service if present.
        4. Creates clamd service with explicit binPath pointing to clamd.conf.
        5. Sets auto-start and failure recovery actions.
        6. Starts clamd service.
        """
        target_dir = clamav_dir.strip() if clamav_dir else ""
        if not target_dir:
            target_dir = ClamAVConfigGenerator.detect_clamav_dir() or ""

        if not target_dir or not os.path.isdir(target_dir):
            return False, f"ClamAV directory not found: {target_dir or '(empty)'}. Please configure bin directory in Settings."

        target_dir = os.path.normpath(target_dir)
        clamd_exe = os.path.join(target_dir, "clamd.exe")
        if not os.path.isfile(clamd_exe):
            # Try searching in subdirectories or parent
            for root, _, files in os.walk(target_dir):
                if "clamd.exe" in files:
                    clamd_exe = os.path.join(root, "clamd.exe")
                    target_dir = root
                    break

        if not os.path.isfile(clamd_exe):
            return False, f"clamd.exe binary not found in {target_dir}"

        # 1. Ensure clamd.conf and database directory exist
        clamd_conf = os.path.join(target_dir, "clamd.conf")
        if not os.path.isfile(clamd_conf):
            logger.info("clamd.conf not found. Auto-generating configuration...")
            ok, msg, _ = ClamAVConfigGenerator.generate_configs_direct(target_dir, overwrite=False)
            if not ok:
                return False, f"Failed to generate clamd.conf: {msg}"

        db_dir = os.path.join(target_dir, "database")
        os.makedirs(db_dir, exist_ok=True)

        # 2. Check and clean up existing service if present
        current_status = cls.get_service_status()
        if current_status == "RUNNING":
            logger.info("Stopping existing clamd service before reinstalling...")
            subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, timeout=10)
            time.sleep(1.0)

        if current_status != "NOT_INSTALLED":
            logger.info("Removing old clamd service registration...")
            subprocess.run(["sc.exe", "delete", SERVICE_NAME], capture_output=True, text=True, timeout=10)
            time.sleep(1.0)

        # 3. Create Windows Service via sc.exe
        bin_path = f'"{clamd_exe}" --service-mode -c "{clamd_conf}"'
        create_cmd = [
            "sc.exe",
            "create",
            SERVICE_NAME,
            f"binPath= {bin_path}",
            "start= auto",
            f"DisplayName= {DISPLAY_NAME}",
        ]
        logger.info(f"Executing: {' '.join(create_cmd)}")
        res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=15)
        if res.returncode != 0 and "SUCCESS" not in res.stdout:
            err = res.stdout.strip() or res.stderr.strip()
            logger.error(f"sc create clamd failed: {err}")
            return False, f"Failed to register Windows service clamd: {err}"

        # 4. Set failure restart recovery
        subprocess.run(
            ["sc.exe", "failure", SERVICE_NAME, "reset= 86400", "actions= restart/5000/restart/10000//"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # 5. Set service description
        subprocess.run(
            ["sc.exe", "description", SERVICE_NAME, DESCRIPTION],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # 6. Start service
        logger.info("Starting clamd service...")
        start_res = subprocess.run(["sc.exe", "start", SERVICE_NAME], capture_output=True, text=True, timeout=15)
        logger.info(f"sc start clamd output: {start_res.stdout.strip()}")

        msg = (
            f"ClamAV ClamD service successfully installed and started!\n"
            f"- Binary: {clamd_exe}\n"
            f"- Config: {clamd_conf}\n"
            f"- Startup: Automatic at Windows boot"
        )
        return True, msg

    @classmethod
    def uninstall_service_direct(cls, clamav_dir: Optional[str] = None) -> Tuple[bool, str]:
        """Directly stops and unregisters the clamd Windows Service (must be elevated)."""
        # Stop service if running
        try:
            subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, timeout=10)
            time.sleep(1.0)
        except Exception as exc:
            logger.debug(f"Error stopping clamd during uninstall: {exc}")

        # Delete service
        res = subprocess.run(["sc.exe", "delete", SERVICE_NAME], capture_output=True, text=True, timeout=10)
        out = (res.stdout + res.stderr).strip()

        if res.returncode == 0 or "SUCCESS" in out.upper() or "1060" in out:
            return True, "ClamAV ClamD Windows Service uninstalled successfully."
        return False, f"Failed to delete service: {out}"

    @classmethod
    def start_service_direct(cls) -> Tuple[bool, str]:
        """Directly starts the clamd Windows Service (must be elevated)."""
        res = subprocess.run(["sc.exe", "start", SERVICE_NAME], capture_output=True, text=True, timeout=15)
        out = (res.stdout + res.stderr).strip()
        if res.returncode == 0 or "START_PENDING" in out.upper() or "RUNNING" in out.upper():
            return True, "ClamD service start command sent."
        return False, f"Failed to start service: {out}"

    @classmethod
    def stop_service_direct(cls) -> Tuple[bool, str]:
        """Directly stops the clamd Windows Service (must be elevated)."""
        res = subprocess.run(["sc.exe", "stop", SERVICE_NAME], capture_output=True, text=True, timeout=15)
        out = (res.stdout + res.stderr).strip()
        if res.returncode == 0 or "STOP_PENDING" in out.upper() or "STOPPED" in out.upper():
            return True, "ClamD service stop command sent."
        return False, f"Failed to stop service: {out}"

    # Elevated wrappers
    @classmethod
    def install_service_elevated(cls, clamav_dir: Optional[str] = None) -> Tuple[bool, str]:
        if is_admin():
            return cls.install_service_direct(clamav_dir)
        arg = f'--install-clamd-service "{clamav_dir}"' if clamav_dir else "--install-clamd-service"
        return _elevate_command(arg)

    @classmethod
    def uninstall_service_elevated(cls, clamav_dir: Optional[str] = None) -> Tuple[bool, str]:
        if is_admin():
            return cls.uninstall_service_direct(clamav_dir)
        arg = f'--uninstall-clamd-service "{clamav_dir}"' if clamav_dir else "--uninstall-clamd-service"
        return _elevate_command(arg)

    @classmethod
    def start_service_elevated(cls) -> Tuple[bool, str]:
        if is_admin():
            return cls.start_service_direct()
        return _elevate_command("--start-clamd-service")

    @classmethod
    def stop_service_elevated(cls) -> Tuple[bool, str]:
        if is_admin():
            return cls.stop_service_direct()
        return _elevate_command("--stop-clamd-service")
