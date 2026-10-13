import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from app.platform_win.startup import (
    APP_NAME,
    RUN_KEY_SUB,
    create_shortcut_file,
    disable_startup,
    enable_startup,
    get_launch_components,
    get_pythonw_path,
    is_startup_registered,
)


def test_get_pythonw_path():
    path = get_pythonw_path()
    assert isinstance(path, str)
    assert len(path) > 0
    # On Windows Python distributions, it usually ends with pythonw.exe or python.exe
    assert path.lower().endswith((".exe", "pythonw", "python"))


def test_get_launch_components():
    exe_path, args, work_dir, icon_path = get_launch_components()
    assert isinstance(exe_path, str)
    assert "--minimized" in args
    assert os.path.isdir(work_dir)
    assert "main.py" in args


def test_enable_and_disable_startup_mocked():
    with patch("winreg.OpenKey") as mock_open_key, \
         patch("winreg.SetValueEx") as mock_set_val, \
         patch("winreg.DeleteValue") as mock_del_val, \
         patch("winreg.QueryValueEx", return_value=("test_cmd", 1)):

        # Test enable
        ok, msg = enable_startup(use_registry=True, use_shortcut=False)
        assert ok is True
        mock_set_val.assert_called_once()

        # Test is_registered
        reg = is_startup_registered()
        assert reg is True

        # Test disable
        ok_dis, _ = disable_startup()
        assert ok_dis is True
        mock_del_val.assert_called_once()


def test_create_shortcut_file_graceful_failure():
    # Attempting to create shortcut in an invalid path or without COM
    with patch("win32com.client.Dispatch", side_effect=Exception("COM not available")):
        ok, msg = create_shortcut_file("C:\\invalid\\path.lnk", "pythonw.exe")
        assert ok is False
        assert "COM not available" in msg
