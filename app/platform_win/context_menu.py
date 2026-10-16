import ctypes
import os
import sys
import winreg
from typing import Optional, Tuple

import win32api
import win32con
from app.core.logger import get_logger

logger = get_logger()

SHELL_KEY_STAR = r"*\shell\ScanWithClamAV"
SHELL_KEY_DIR = r"Directory\shell\ScanWithClamAV"
HKCU_SHELL_STAR = r"Software\Classes\*\shell\ScanWithClamAV"
HKCU_SHELL_DIR = r"Software\Classes\Directory\shell\ScanWithClamAV"
MENU_LABEL = "Scan with ClamAV"

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def get_launch_command() -> str:
    """Builds the command string for context menu invocation."""
    if getattr(sys, "frozen", False):
        exe_path = sys.executable
        return f'"{exe_path}" --scan-path "%1"'
    else:
        # Prefer pythonw.exe to prevent console window popup on right-click
        python_dir = os.path.dirname(sys.executable)
        pythonw_exe = os.path.join(python_dir, "pythonw.exe")
        python_bin = pythonw_exe if os.path.isfile(pythonw_exe) else sys.executable

        # Locate main.py in project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        main_py = os.path.join(project_root, "main.py")
        return f'"{python_bin}" "{main_py}" --scan-path "%1"'

def is_context_menu_registered() -> bool:
    # Check HKCU first (user-level, non-elevated)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, HKCU_SHELL_STAR + r"\command", 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug(f"Error checking HKCU registry status: {exc}")

    # Check HKCR (system-wide)
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, SHELL_KEY_STAR + r"\command", 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False
    except Exception as exc:
        logger.debug(f"Error checking registry status: {exc}")
        return False

def register_context_menu_direct() -> Tuple[bool, str]:
    """Registers context menu keys in HKCU (zero admin elevation needed) and HKCR if admin."""
    command_str = get_launch_command()
    exe_icon = sys.executable

    # 1. Register in HKCU (user-level: completely silent, no UAC prompt needed)
    try:
        for sub_key in (HKCU_SHELL_STAR, HKCU_SHELL_DIR):
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MENU_LABEL)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, exe_icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub_key + r"\command") as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, command_str)

        logger.info(f"Registered Windows Explorer context menu in HKCU: {command_str}")
        return True, "Successfully registered context menu integration."
    except Exception as exc:
        logger.error(f"Failed to register context menu in HKCU: {exc}")
        return False, str(exc)

def unregister_context_menu_direct() -> Tuple[bool, str]:
    """Deletes context menu keys from HKCU and HKCR."""
    # 1. Delete from HKCU
    for base_sub in (HKCU_SHELL_STAR, HKCU_SHELL_DIR):
        try:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base_sub + r"\command")
            except FileNotFoundError:
                pass
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base_sub)
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.debug(f"Error unregistering HKCU context menu key {base_sub}: {exc}")

    # 2. Delete from HKCR if present/admin
    for base_sub in (SHELL_KEY_STAR, SHELL_KEY_DIR):
        try:
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, base_sub + r"\command")
            except FileNotFoundError:
                pass
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, base_sub)
        except Exception:
            pass

    logger.info("Unregistered Windows Explorer context menu.")
    return True, "Successfully unregistered context menu integration."

def register_context_menu_elevated() -> Tuple[bool, str]:
    """Registers context menu, automatically prompting UAC if not currently admin."""
    if is_admin():
        return register_context_menu_direct()

    # Request elevation
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_py = os.path.join(project_root, "main.py")
    
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = "--register-context-menu"
    else:
        exe = sys.executable
        params = f'"{main_py}" --register-context-menu'

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
            return True, "Requested administrator elevation to register context menu."
        else:
            return False, f"Failed to elevate process (code: {ret})"
    except Exception as exc:
        return False, f"UAC prompt cancelled or failed: {exc}"

def unregister_context_menu_elevated() -> Tuple[bool, str]:
    """Unregisters context menu, automatically prompting UAC if not currently admin."""
    if is_admin():
        return unregister_context_menu_direct()

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_py = os.path.join(project_root, "main.py")

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = "--unregister-context-menu"
    else:
        exe = sys.executable
        params = f'"{main_py}" --unregister-context-menu'

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
            return True, "Requested administrator elevation to unregister context menu."
        else:
            return False, f"Failed to elevate process (code: {ret})"
    except Exception as exc:
        return False, f"UAC prompt cancelled or failed: {exc}"
