import ctypes
import ctypes.wintypes
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


def wait_for_clamd_socket(host: str = "127.0.0.1", port: int = 3310, timeout: float = 20.0) -> bool:
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


def _elevate_command(param_str: str, timeout_sec: int = 45) -> Tuple[bool, str]:
    """
    Helper to launch main.py with elevated administrative rights via UAC and WAIT for completion.
    Uses ShellExecuteExW with SEE_MASK_NOCLOSEPROCESS to capture the exit code.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_py = os.path.join(project_root, "main.py")

    # Prefer python.exe over pythonw.exe for elevated runner so standard streams exist
    python_dir = os.path.dirname(sys.executable)
    python_exe = os.path.join(python_dir, "python.exe")
    exe = python_exe if os.path.isfile(python_exe) else sys.executable

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = param_str
    else:
        params = f'"{main_py}" {param_str}'

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.wintypes.DWORD),
            ("fMask", ctypes.wintypes.ULONG),
            ("hwnd", ctypes.wintypes.HWND),
            ("lpVerb", ctypes.wintypes.LPCWSTR),
            ("lpFile", ctypes.wintypes.LPCWSTR),
            ("lpParameters", ctypes.wintypes.LPCWSTR),
            ("lpDirectory", ctypes.wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.wintypes.LPCWSTR),
            ("hkeyClass", ctypes.wintypes.HKEY),
            ("dwHotKey", ctypes.wintypes.DWORD),
            ("hIconOrMonitor", ctypes.wintypes.HANDLE),
            ("hProcess", ctypes.wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SW_HIDE = 0

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = exe
    sei.lpParameters = params
    sei.lpDirectory = project_root
    sei.nShow = SW_HIDE

    try:
        ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            err = ctypes.GetLastError()
            if err == 1223:  # ERROR_CANCELLED
                return False, "Administrator elevation prompt was cancelled by user."
            return False, f"Failed to elevate process (error code: {err})"

        hProcess = sei.hProcess
        if hProcess:
            # Wait for elevated process to finish
            ctypes.windll.kernel32.WaitForSingleObject(hProcess, timeout_sec * 1000)
            exit_code = ctypes.wintypes.DWORD()
            ctypes.windll.kernel32.GetExitCodeProcess(hProcess, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(hProcess)

            if exit_code.value == 0:
                return True, "Operation completed successfully with administrative privileges."
            else:
                return False, f"Elevated operation failed with exit code: {exit_code.value}"

        return True, "Elevated command executed."
    except Exception as exc:
        return False, f"Elevation failed: {exc}"


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
        4. Creates clamd service via Win32 API (or sc.exe fallback) with explicit binPath pointing to clamd.conf.
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

        # MANDATORY: ClamAV on Windows checks if (daemon_mode) before calling StartServiceCtrlDispatcher!
        # Both --daemon and --service-mode MUST be present.
        bin_path = f'"{clamd_exe}" --daemon --service-mode -c "{clamd_conf}"'

        # 2. Stop and remove existing service if present
        cls.uninstall_service_direct()
        time.sleep(1.0)

        # 3. Create service via Win32 API
        service_created = False
        try:
            import win32service

            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            try:
                svc = win32service.CreateService(
                    scm,
                    SERVICE_NAME,
                    DISPLAY_NAME,
                    win32service.SERVICE_ALL_ACCESS,
                    win32service.SERVICE_WIN32_OWN_PROCESS,
                    win32service.SERVICE_AUTO_START,
                    win32service.SERVICE_ERROR_NORMAL,
                    bin_path,
                    None,
                    0,
                    None,
                    None,
                    None,
                )
                try:
                    win32service.ChangeServiceConfig2(svc, win32service.SERVICE_CONFIG_DESCRIPTION, DESCRIPTION)
                except Exception as exc:
                    logger.debug(f"Could not set service description: {exc}")

                win32service.CloseServiceHandle(svc)
                service_created = True
                logger.info("Created clamd service via Win32 API.")
            finally:
                win32service.CloseServiceHandle(scm)
        except Exception as exc:
            logger.warning(f"Win32 CreateService failed, attempting sc.exe fallback: {exc}")

        # Fallback to raw sc.exe command if Win32 API failed
        if not service_created:
            raw_cmd = f'sc.exe create {SERVICE_NAME} binPath= "\"{clamd_exe}\" --daemon --service-mode -c \"{clamd_conf}\"" start= auto DisplayName= "{DISPLAY_NAME}"'
            logger.info(f"Executing fallback: {raw_cmd}")
            res = subprocess.run(raw_cmd, shell=False, capture_output=True, text=True, timeout=15)
            if res.returncode != 0 and "SUCCESS" not in res.stdout.upper():
                err = res.stdout.strip() or res.stderr.strip()
                logger.error(f"sc create clamd failed: {err}")
                return False, f"Failed to register Windows service clamd: {err}"

        # 4. Set failure restart recovery
        try:
            subprocess.run(
                f"sc.exe failure {SERVICE_NAME} reset= 86400 actions= restart/5000/restart/10000//",
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as exc:
            logger.debug(f"Could not set service failure recovery: {exc}")

        # 5. Start service
        logger.info("Starting clamd service...")
        start_ok, start_msg = cls.start_service_direct()
        logger.info(f"Start service result: {start_ok} - {start_msg}")

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
        # Stop service first
        cls.stop_service_direct()
        time.sleep(1.0)

        # Try Win32 API delete
        try:
            import pywintypes
            import win32service

            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            try:
                try:
                    svc = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
                    win32service.DeleteService(svc)
                    win32service.CloseServiceHandle(svc)
                    logger.info("Deleted clamd service via Win32 API.")
                    return True, "ClamAV ClamD Windows Service uninstalled successfully."
                except pywintypes.error as e:
                    if e.winerror == 1060:
                        return True, "Service is not installed."
            finally:
                win32service.CloseServiceHandle(scm)
        except Exception as exc:
            logger.debug(f"Win32 DeleteService error: {exc}")

        # Fallback to sc.exe delete
        res = subprocess.run(f"sc.exe delete {SERVICE_NAME}", shell=False, capture_output=True, text=True, timeout=10)
        out = (res.stdout + res.stderr).strip()
        if res.returncode == 0 or "SUCCESS" in out.upper() or "1060" in out:
            return True, "ClamAV ClamD Windows Service uninstalled successfully."
        return False, f"Failed to delete service: {out}"

    @classmethod
    def _ensure_service_binpath(cls) -> None:
        """Fixes existing service registration if --daemon flag is missing from binary path."""
        try:
            import win32service

            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            try:
                svc = win32service.OpenService(
                    scm,
                    SERVICE_NAME,
                    win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_CHANGE_CONFIG,
                )
                try:
                    cfg = win32service.QueryServiceConfig(svc)
                    current_path = cfg[3]
                    if "--daemon" not in current_path:
                        clamav_dir = ClamAVConfigGenerator.detect_clamav_dir() or ""
                        if clamav_dir:
                            clamd_exe = os.path.join(clamav_dir, "clamd.exe")
                            clamd_conf = os.path.join(clamav_dir, "clamd.conf")
                            new_path = f'"{clamd_exe}" --daemon --service-mode -c "{clamd_conf}"'
                            win32service.ChangeServiceConfig(
                                svc,
                                win32service.SERVICE_NO_CHANGE,
                                win32service.SERVICE_NO_CHANGE,
                                win32service.SERVICE_NO_CHANGE,
                                new_path,
                                None,
                                0,
                                None,
                                None,
                                None,
                                None,
                            )
                            logger.info(f"Updated clamd service binary path to include --daemon: {new_path}")
                finally:
                    win32service.CloseServiceHandle(svc)
            finally:
                win32service.CloseServiceHandle(scm)
        except Exception as exc:
            logger.debug(f"Could not auto-update service binary path: {exc}")

    @classmethod
    def start_service_direct(cls) -> Tuple[bool, str]:
        """Directly starts the clamd Windows Service (must be elevated)."""
        cls._ensure_service_binpath()

        # Try Win32 API start
        try:
            import win32serviceutil

            win32serviceutil.StartService(SERVICE_NAME)
            return True, "ClamD service start command sent."
        except Exception as exc:
            logger.debug(f"win32serviceutil StartService: {exc}")

        # Fallback to sc.exe start
        res = subprocess.run(f"sc.exe start {SERVICE_NAME}", shell=False, capture_output=True, text=True, timeout=15)
        out = (res.stdout + res.stderr).strip()
        if res.returncode == 0 or "START_PENDING" in out.upper() or "RUNNING" in out.upper() or "1056" in out:
            return True, "ClamD service start command sent."
        return False, f"Failed to start service: {out}"

    @classmethod
    def stop_service_direct(cls) -> Tuple[bool, str]:
        """Directly stops the clamd Windows Service (must be elevated)."""
        try:
            import win32serviceutil

            win32serviceutil.StopService(SERVICE_NAME)
            return True, "ClamD service stop command sent."
        except Exception as exc:
            logger.debug(f"win32serviceutil StopService: {exc}")

        res = subprocess.run(f"sc.exe stop {SERVICE_NAME}", shell=False, capture_output=True, text=True, timeout=15)
        out = (res.stdout + res.stderr).strip()
        if res.returncode == 0 or "STOP_PENDING" in out.upper() or "STOPPED" in out.upper() or "1062" in out:
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
