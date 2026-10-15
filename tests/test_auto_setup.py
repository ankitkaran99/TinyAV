import os
from unittest.mock import MagicMock, patch
import pytest

from app.core.auto_setup import AutoProvisioner
from app.core.binary_updater import ClamAVReleaseInfo, ReleaseAsset
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine


@pytest.fixture
def mock_engine():
    engine = MagicMock(spec=ClamAVEngine)
    engine.is_available.return_value = False
    return engine


@pytest.fixture
def mock_config_mgr(tmp_path):
    config_file = str(tmp_path / "config.json")
    mgr = ConfigManager(config_path=config_file)
    return mgr


def test_is_setup_needed(mock_engine):
    assert AutoProvisioner.is_setup_needed(mock_engine) is True
    mock_engine.is_available.return_value = True
    assert AutoProvisioner.is_setup_needed(mock_engine) is False


def test_get_default_install_dir():
    d = AutoProvisioner.get_default_install_dir()
    assert os.path.basename(d) == "ClamAV"
    assert "Programs" in d


def test_do_provisioning_success(mock_config_mgr, mock_engine, tmp_path):
    provisioner = AutoProvisioner(mock_config_mgr, mock_engine)
    target_dir = str(tmp_path / "clamav_install")

    fake_asset = ReleaseAsset(
        name="clamav-1.5.4.win.x64.zip",
        size=1000,
        download_url="https://example.com/fake.zip",
        content_type="application/zip",
    )
    fake_release = ClamAVReleaseInfo(
        tag_name="clamav-1.5.4",
        version="1.5.4",
        release_name="ClamAV 1.5.4",
        html_url="https://github.com/fake",
        published_at="2026-10-15",
        zip_asset=fake_asset,
    )

    with patch.object(provisioner.binary_updater, "check_for_updates", return_value=(True, "OK", fake_release)), \
         patch.object(provisioner.binary_updater, "download_file", return_value=(True, "Downloaded")), \
         patch("app.core.binary_updater.ClamAVBinaryUpdater.apply_zip_update_direct", return_value=(True, "Extracted", 10)), \
         patch("app.core.config_generator.ClamAVConfigGenerator.generate_configs_direct", return_value=(True, "Configured", [])), \
         patch("app.platform_win.service_manager.ClamDServiceManager.install_service_elevated", return_value=(True, "Service installed")), \
         patch("app.platform_win.service_manager.wait_for_clamd_socket", return_value=True):

        ok, msg = provisioner._do_provisioning(target_dir)
        assert ok is True
        assert "installed and configured successfully" in msg
        assert mock_config_mgr.config.clamav_bin_dir == target_dir
        assert mock_config_mgr.config.prefer_clamd is True


def test_do_provisioning_download_failure(mock_config_mgr, mock_engine, tmp_path):
    provisioner = AutoProvisioner(mock_config_mgr, mock_engine)
    target_dir = str(tmp_path / "clamav_install")

    fake_asset = ReleaseAsset(
        name="clamav-1.5.4.win.x64.zip",
        size=1000,
        download_url="https://example.com/fake.zip",
        content_type="application/zip",
    )
    fake_release = ClamAVReleaseInfo(
        tag_name="clamav-1.5.4",
        version="1.5.4",
        release_name="ClamAV 1.5.4",
        html_url="https://github.com/fake",
        published_at="2026-10-15",
        zip_asset=fake_asset,
    )

    with patch.object(provisioner.binary_updater, "check_for_updates", return_value=(True, "OK", fake_release)), \
         patch.object(provisioner.binary_updater, "download_file", return_value=(False, "Network connection timed out")):

        ok, msg = provisioner._do_provisioning(target_dir)
        assert ok is False
        assert "Download failed" in msg
