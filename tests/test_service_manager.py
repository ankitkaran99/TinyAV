from unittest.mock import MagicMock, patch
import os
import pytest

from app.platform_win.service_manager import (
    ClamDServiceManager,
    get_clamd_service_status,
    is_admin,
    is_clamd_service_installed,
    is_clamd_service_running,
    wait_for_clamd_socket,
)


def test_is_admin():
    with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
        assert is_admin() is True
    with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
        assert is_admin() is False


def test_get_clamd_service_status_win32():
    with patch("win32serviceutil.QueryServiceStatus") as mock_query:
        import win32service

        mock_query.return_value = (0, win32service.SERVICE_RUNNING, 0, 0, 0, 0, 0)
        assert get_clamd_service_status() == "RUNNING"
        assert is_clamd_service_running() is True
        assert is_clamd_service_installed() is True

        mock_query.return_value = (0, win32service.SERVICE_STOPPED, 0, 0, 0, 0, 0)
        assert get_clamd_service_status() == "STOPPED"
        assert is_clamd_service_running() is False
        assert is_clamd_service_installed() is True


def test_get_clamd_service_status_not_installed():
    import pywintypes

    with patch("win32serviceutil.QueryServiceStatus", side_effect=pywintypes.error(1060, "OpenService", "Does not exist")):
        assert get_clamd_service_status() == "NOT_INSTALLED"
        assert is_clamd_service_installed() is False
        assert is_clamd_service_running() is False


def test_get_clamd_service_status_sc_fallback():
    with patch("win32serviceutil.QueryServiceStatus", side_effect=Exception("win32 failure")):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="STATE : 4 RUNNING", stderr="")
            assert get_clamd_service_status() == "RUNNING"

            mock_run.return_value = MagicMock(returncode=1, stdout="FAILED 1060: The specified service does not exist", stderr="")
            assert get_clamd_service_status() == "NOT_INSTALLED"


def test_install_service_direct_dir_not_found(tmp_path):
    non_existent = str(tmp_path / "does_not_exist")
    ok, msg = ClamDServiceManager.install_service_direct(non_existent)
    assert ok is False
    assert "not found" in msg.lower()


def test_install_service_direct_clamd_exe_not_found(tmp_path):
    empty_dir = str(tmp_path / "clamav")
    os.makedirs(empty_dir, exist_ok=True)
    ok, msg = ClamDServiceManager.install_service_direct(empty_dir)
    assert ok is False
    assert "clamd.exe binary not found" in msg


def test_install_service_direct_success(tmp_path):
    clamav_dir = tmp_path / "clamav"
    clamav_dir.mkdir()
    clamd_exe = clamav_dir / "clamd.exe"
    clamd_exe.write_text("mock binary")

    with patch("subprocess.run") as mock_run, patch.object(ClamDServiceManager, "get_service_status", return_value="NOT_INSTALLED"):
        mock_run.return_value = MagicMock(returncode=0, stdout="[SC] CreateService SUCCESS", stderr="")
        ok, msg = ClamDServiceManager.install_service_direct(str(clamav_dir))
        assert ok is True
        assert "successfully installed" in msg
        # Verify clamd.conf was generated
        assert (clamav_dir / "clamd.conf").is_file()
        assert (clamav_dir / "database").is_dir()


def test_uninstall_service_direct():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="[SC] DeleteService SUCCESS", stderr="")
        ok, msg = ClamDServiceManager.uninstall_service_direct()
        assert ok is True
        assert "uninstalled" in msg.lower()


def test_start_stop_service_direct():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="START_PENDING", stderr="")
        ok, msg = ClamDServiceManager.start_service_direct()
        assert ok is True

        mock_run.return_value = MagicMock(returncode=0, stdout="STOP_PENDING", stderr="")
        ok, msg = ClamDServiceManager.stop_service_direct()
        assert ok is True


def test_elevated_service_calls(tmp_path):
    with patch("app.platform_win.service_manager.is_admin", return_value=False), patch("win32api.ShellExecute", return_value=42) as mock_shell:
        ok, msg = ClamDServiceManager.install_service_elevated(str(tmp_path))
        assert ok is True
        assert mock_shell.called
        assert "runas" in mock_shell.call_args[0]

        ok, msg = ClamDServiceManager.start_service_elevated()
        assert ok is True

        ok, msg = ClamDServiceManager.stop_service_elevated()
        assert ok is True

        ok, msg = ClamDServiceManager.uninstall_service_elevated()
        assert ok is True


def test_wait_for_clamd_socket():
    with patch("clamd.ClamdNetworkSocket") as mock_socket:
        mock_client = MagicMock()
        mock_client.ping.return_value = "PONG"
        mock_socket.return_value = mock_client

        assert wait_for_clamd_socket(timeout=1.0) is True

    with patch("clamd.ClamdNetworkSocket", side_effect=Exception("Connection refused")):
        assert wait_for_clamd_socket(timeout=0.6) is False
