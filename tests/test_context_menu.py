import os
import sys
from unittest.mock import MagicMock, patch
import pytest

from app.platform_win import context_menu


def test_get_launch_command_unfrozen():
    with patch.object(sys, "frozen", False, create=True):
        cmd = context_menu.get_launch_command()
        assert "--scan-path \"%1\"" in cmd
        assert "main.py" in cmd


def test_get_launch_command_frozen():
    with patch.object(sys, "frozen", True, create=True):
        with patch.object(sys, "executable", r"C:\Program Files\TinyAV\TinyAV.exe"):
            cmd = context_menu.get_launch_command()
            assert cmd == r'"C:\Program Files\TinyAV\TinyAV.exe" --scan-path "%1"'


def test_is_context_menu_registered_hkcu():
    with patch("winreg.OpenKey", return_value=MagicMock()) as mock_open:
        assert context_menu.is_context_menu_registered() is True
        mock_open.assert_called_once()


def test_is_context_menu_registered_hkcr():
    # Fail first call (HKCU), succeed second call (HKCR)
    def side_effect(root, subkey, *args, **kwargs):
        if "Software\\Classes" in subkey:
            raise FileNotFoundError()
        return MagicMock()

    with patch("winreg.OpenKey", side_effect=side_effect):
        assert context_menu.is_context_menu_registered() is True


def test_is_context_menu_registered_not_found():
    with patch("winreg.OpenKey", side_effect=FileNotFoundError()):
        assert context_menu.is_context_menu_registered() is False


def test_register_context_menu_direct():
    with patch("winreg.CreateKey") as mock_create, \
         patch("winreg.SetValueEx") as mock_set:
        mock_key = MagicMock()
        mock_create.return_value.__enter__.return_value = mock_key

        success, msg = context_menu.register_context_menu_direct()
        assert success is True
        assert "Successfully registered" in msg
        assert mock_set.call_count >= 6  # 2 keys * (label + icon + command)


def test_unregister_context_menu_direct():
    with patch("winreg.DeleteKey") as mock_del:
        success, msg = context_menu.unregister_context_menu_direct()
        assert success is True
        assert "Successfully unregistered" in msg
        assert mock_del.call_count >= 4
