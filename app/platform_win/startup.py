import os
import sys
import winreg
from typing import Optional, Tuple

from app.core.logger import get_logger

logger = get_logger()

RUN_KEY_SUB = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "TinyAV"


def get_pythonw_path() -> str:
    """Returns absolute path to pythonw.exe to ensure no console window is created."""
    if getattr(sys, "frozen", False):
        return sys.executable

    py_dir = os.path.dirname(sys.executable)
    pyw = os.path.join(py_dir, "pythonw.exe")
    if os.path.isfile(pyw):
        return pyw
    return sys.executable


def get_launch_components() -> Tuple[str, str, str, str]:
    """
    Returns (exe_path, args, working_dir, icon_path).
    Guarantees pythonw.exe is used so NO cmd or console window ever shows up.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    icon_path = os.path.join(project_root, "app", "assets", "icon.ico")
    if not os.path.isfile(icon_path):
        icon_path = ""

    if getattr(sys, "frozen", False):
        return sys.executable, "--minimized", os.path.dirname(sys.executable), icon_path

    exe_path = get_pythonw_path()
    main_py = os.path.join(project_root, "main.py")
    args = f'"{main_py}" --minimized'
    return exe_path, args, project_root, icon_path


def is_startup_registered() -> bool:
    """Checks if TinyAV is registered in HKCU Run registry or Startup folder."""
    # 1. Check HKCU Run registry
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_SUB, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_NAME)
            if val:
                return True
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug(f"Error reading Run registry key: {exc}")

    # 2. Check Startup folder shortcut
    startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    lnk_path = os.path.join(startup_dir, "TinyAV.lnk")
    return os.path.isfile(lnk_path)


def enable_startup(use_registry: bool = True, use_shortcut: bool = True) -> Tuple[bool, str]:
    """
    Registers TinyAV to start at Windows login directly into the tray with ZERO console windows.
    - Uses HKCU Run registry (primary, 100% silent, standard for Windows).
    - Can also place a .lnk in Startup folder targeting pythonw.exe with WindowStyle=7.
    """
    exe_path, args, work_dir, icon_path = get_launch_components()
    full_cmd = f'"{exe_path}" {args}'
    success = False
    messages = []

    # 1. Register in HKCU Run (No admin required, zero cmd windows)
    if use_registry:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_SUB, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, full_cmd)
            logger.info(f"Registered TinyAV in HKCU Run key: {full_cmd}")
            messages.append("Registry auto-start enabled")
            success = True
        except Exception as exc:
            logger.error(f"Failed to write to HKCU Run key: {exc}")
            messages.append(f"Registry failed: {exc}")

    # 2. Setup .lnk in Startup folder targeting pythonw.exe
    if use_shortcut:
        startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        lnk_path = os.path.join(startup_dir, "TinyAV.lnk")
        ok, msg = create_shortcut_file(
            shortcut_path=lnk_path,
            target_exe=exe_path,
            arguments=args,
            working_dir=work_dir,
            icon_path=icon_path,
            description="TinyAV Antivirus Companion (Minimized to Tray)",
            minimized=True,
        )
        if ok:
            messages.append("Startup folder shortcut created")
            success = True
        else:
            messages.append(f"Shortcut warning: {msg}")

    result_msg = "; ".join(messages)
    return success, result_msg


def disable_startup() -> Tuple[bool, str]:
    """Removes TinyAV from both HKCU Run registry and Windows Startup folder."""
    removed_any = False

    # 1. Remove from HKCU Run
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_SUB, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
        logger.info("Removed TinyAV from HKCU Run key")
        removed_any = True
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.warning(f"Error removing HKCU Run key: {exc}")

    # 2. Remove Startup folder shortcut
    startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    lnk_path = os.path.join(startup_dir, "TinyAV.lnk")
    if os.path.isfile(lnk_path):
        try:
            os.remove(lnk_path)
            logger.info(f"Removed startup shortcut: {lnk_path}")
            removed_any = True
        except Exception as exc:
            logger.warning(f"Error removing startup shortcut: {exc}")

    return True, "Auto-start disabled (removed registry entry and startup shortcuts)."


def create_shortcut_file(
    shortcut_path: str,
    target_exe: str,
    arguments: str = "",
    working_dir: str = "",
    icon_path: str = "",
    description: str = "",
    minimized: bool = False,
) -> Tuple[bool, str]:
    """
    Creates a Windows .lnk shortcut using WScript.Shell.
    WindowStyle: 7 = Minimized, 1 = Normal.
    """
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = target_exe
        shortcut.Arguments = arguments
        shortcut.WorkingDirectory = working_dir or os.path.dirname(target_exe)
        shortcut.Description = description
        if minimized:
            shortcut.WindowStyle = 7  # 7 = Minimized window
        if icon_path and os.path.isfile(icon_path):
            shortcut.IconLocation = f"{icon_path},0"
        shortcut.Save()
        logger.info(f"Created shortcut: {shortcut_path} -> {target_exe}")
        return True, f"Created shortcut: {shortcut_path}"
    except Exception as exc:
        logger.error(f"Failed to create shortcut {shortcut_path}: {exc}")
        return False, str(exc)
