import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from app.platform_win import autorun_immunizer
from app.platform_win.win_drives import DriveInfo


def test_is_drive_writable_true():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert autorun_immunizer.is_drive_writable(tmpdir) is True


def test_is_drive_writable_nonexistent():
    assert autorun_immunizer.is_drive_writable(r"Z:\NonExistentDrive") is False


def test_immunize_drive_renames_autorun():
    with tempfile.TemporaryDirectory() as tmpdir:
        autorun_path = os.path.join(tmpdir, "autorun.inf")
        with open(autorun_path, "w") as f:
            f.write("[autorun]\nopen=malware.exe\n")

        success, msg = autorun_immunizer.immunize_drive(tmpdir)
        assert success is True
        assert "Successfully immunized" in msg

        # Verify autorun.inf is gone and autorun.inf.tiny exists
        assert not os.path.exists(autorun_path)
        target_path = os.path.join(tmpdir, "autorun.inf.tiny")
        assert os.path.exists(target_path)
        with open(target_path, "r") as f:
            assert "malware.exe" in f.read()


def test_immunize_drive_no_autorun():
    with tempfile.TemporaryDirectory() as tmpdir:
        success, msg = autorun_immunizer.immunize_drive(tmpdir)
        assert success is False
        assert "No autorun.inf found" in msg


def test_immunize_drive_readonly_drive():
    with tempfile.TemporaryDirectory() as tmpdir:
        autorun_path = os.path.join(tmpdir, "autorun.inf")
        with open(autorun_path, "w") as f:
            f.write("[autorun]\n")

        with patch("app.platform_win.autorun_immunizer.is_drive_writable", return_value=False):
            success, msg = autorun_immunizer.immunize_drive(tmpdir)
            assert success is False
            assert "write-protected or read-only" in msg
            assert os.path.exists(autorun_path)


def test_immunize_drive_overwrites_existing_tiny():
    with tempfile.TemporaryDirectory() as tmpdir:
        autorun_path = os.path.join(tmpdir, "autorun.inf")
        with open(autorun_path, "w") as f:
            f.write("new content")

        old_tiny = os.path.join(tmpdir, "autorun.inf.tiny")
        with open(old_tiny, "w") as f:
            f.write("old content")

        success, msg = autorun_immunizer.immunize_drive(tmpdir)
        assert success is True
        assert not os.path.exists(autorun_path)
        with open(old_tiny, "r") as f:
            assert f.read() == "new content"


def test_immunize_drive_handles_readonly_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        autorun_path = os.path.join(tmpdir, "autorun.inf")
        with open(autorun_path, "w") as f:
            f.write("[autorun]\nicon=drive.ico\n")
        os.chmod(autorun_path, 0o444)

        success, msg = autorun_immunizer.immunize_drive(tmpdir)
        assert success is True
        assert not os.path.exists(autorun_path)
        target = os.path.join(tmpdir, "autorun.inf.tiny")
        assert os.path.exists(target)


def test_immunize_all_removable_drives():
    mock_drives = [
        DriveInfo(letter="C:\\", label="OS", is_removable=False, is_fixed=True, serial_number="1", filesystem="NTFS"),
        DriveInfo(letter="E:\\", label="USB", is_removable=True, is_fixed=False, serial_number="2", filesystem="FAT32"),
    ]
    with patch("app.platform_win.win_drives.DriveDetector.get_all_drives", return_value=mock_drives):
        with patch("app.platform_win.autorun_immunizer.immunize_drive", return_value=(True, "ok")) as mock_imm:
            count = autorun_immunizer.immunize_all_removable_drives()
            assert count == 1
            mock_imm.assert_called_once_with("E:\\")
