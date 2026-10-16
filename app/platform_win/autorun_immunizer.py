import os
import shutil
from typing import Optional, Tuple

from app.core.logger import get_logger
from app.platform_win.win_drives import DriveDetector, DriveInfo

logger = get_logger()


def is_drive_writable(drive_path: str) -> bool:
    """
    Checks if a drive root or directory is writable.
    Handles read-only flash drives, CD-ROMs, and hardware write-protected media.
    """
    if not os.path.exists(drive_path):
        return False
    test_file = os.path.join(drive_path, f".tinyav_write_test_{os.getpid()}.tmp")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return True
    except (PermissionError, OSError):
        return False


def _clear_file_attributes(file_path: str) -> None:
    """Clears Windows Read-Only, Hidden, and System attributes so file can be renamed or modified."""
    if os.name == "nt":
        try:
            import win32file, win32con
            win32file.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_NORMAL)
            return
        except Exception:
            pass
    try:
        os.chmod(file_path, 0o777)
    except Exception:
        pass


def immunize_drive(drive_letter: str) -> Tuple[bool, str]:
    """
    If 'autorun.inf' exists on a writable removable drive, clears any hidden/read-only/system
    attributes and renames it to 'autorun.inf.tiny'.

    Returns:
        (immunized: bool, message: str)
        immunized is True only if autorun.inf was found and successfully renamed.
    """
    if not drive_letter:
        return False, "Invalid drive specified."

    drive_root = drive_letter if drive_letter.endswith("\\") else f"{drive_letter}\\"
    autorun_path = os.path.join(drive_root, "autorun.inf")
    target_path = os.path.join(drive_root, "autorun.inf.tiny")

    if not os.path.exists(autorun_path):
        return False, f"No autorun.inf found on {drive_root}"

    # Only process if drive is writable
    if not is_drive_writable(drive_root):
        msg = f"Removable drive {drive_root} is write-protected or read-only. Cannot immunize autorun.inf."
        logger.info(msg)
        return False, msg

    try:
        # Clear attributes on autorun.inf
        _clear_file_attributes(autorun_path)

        # If autorun.inf.tiny already exists, remove it first to avoid collision
        if os.path.exists(target_path):
            _clear_file_attributes(target_path)
            try:
                if os.path.isdir(target_path):
                    shutil.rmtree(target_path)
                else:
                    os.remove(target_path)
            except Exception as e:
                logger.debug(f"Could not remove existing {target_path}: {e}")

        # Rename autorun.inf -> autorun.inf.tiny
        if os.path.isdir(autorun_path):
            shutil.move(autorun_path, target_path)
        else:
            os.replace(autorun_path, target_path)

        msg = f"Successfully immunized USB drive {drive_root}: renamed autorun.inf to autorun.inf.tiny."
        logger.info(msg)
        return True, msg

    except Exception as exc:
        err_msg = f"Failed to rename autorun.inf on {drive_root}: {exc}"
        logger.error(err_msg)
        return False, err_msg


def immunize_all_removable_drives() -> int:
    """
    Scans all connected removable drives and immunizes any that contain autorun.inf.
    Returns count of drives successfully immunized.
    """
    count = 0
    drives = DriveDetector.get_all_drives()
    for d in drives:
        if d.is_removable:
            ok, _ = immunize_drive(d.letter)
            if ok:
                count += 1
    return count
