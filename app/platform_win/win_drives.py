from dataclasses import dataclass
from typing import List, Optional
import win32api
import win32file

@dataclass
class DriveInfo:
    letter: str  # e.g. "C:\"
    label: str   # e.g. "System" or "USB Disk"
    is_removable: bool
    is_fixed: bool
    serial_number: str
    filesystem: str

class DriveDetector:
    @staticmethod
    def get_all_drives() -> List[DriveInfo]:
        results: List[DriveInfo] = []
        try:
            drive_strings = win32api.GetLogicalDriveStrings().split("\000")[:-1]
        except Exception:
            return results

        # Suppress Windows error dialog boxes for unready drives (empty CD/DVD, card readers)
        old_error_mode = 0
        try:
            import win32con
            old_error_mode = win32api.SetErrorMode(win32con.SEM_FAILCRITICALERRORS | win32con.SEM_NOOPENFILEERRORBOX)
        except Exception:
            pass

        try:
            for d in drive_strings:
                try:
                    dtype = win32file.GetDriveType(d)
                    is_removable = (dtype == win32file.DRIVE_REMOVABLE)
                    is_fixed = (dtype == win32file.DRIVE_FIXED)
                    label = ""
                    serial_hex = ""
                    fs_name = ""
                    try:
                        vol_info = win32api.GetVolumeInformation(d)
                        label = vol_info[0] or ("Removable Disk" if is_removable else "Local Disk")
                        serial_hex = hex(vol_info[1] & 0xFFFFFFFF)
                        fs_name = vol_info[4]
                    except Exception:
                        label = "Removable Disk" if is_removable else "Local Disk"

                    results.append(DriveInfo(
                        letter=d,
                        label=label,
                        is_removable=is_removable,
                        is_fixed=is_fixed,
                        serial_number=serial_hex,
                        filesystem=fs_name,
                    ))
                except Exception:
                    continue
        finally:
            if old_error_mode:
                try:
                    win32api.SetErrorMode(old_error_mode)
                except Exception:
                    pass

        return results

    @staticmethod
    def get_fixed_drive_letters() -> List[str]:
        return [d.letter for d in DriveDetector.get_all_drives() if d.is_fixed]

    @staticmethod
    def get_removable_drive_letters() -> List[str]:
        return [d.letter for d in DriveDetector.get_all_drives() if d.is_removable]

    @staticmethod
    def get_drive_info(drive_letter: str) -> Optional[DriveInfo]:
        if not drive_letter.endswith("\\"):
            drive_letter += "\\"
        for d in DriveDetector.get_all_drives():
            if d.letter.upper() == drive_letter.upper():
                return d
        return None
