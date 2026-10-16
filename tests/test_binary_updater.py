import io
import json
import os
import tempfile
import urllib.request
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from app.core.binary_updater import (
    ClamAVBinaryUpdater,
    get_system_arch,
    parse_version_tuple,
)
from app.core.config import ConfigManager
from app.core.engine import ClamAVEngine


def test_system_arch():
    arch = get_system_arch()
    assert arch in ("x64", "arm64", "win32")


def test_parse_version_tuple():
    assert parse_version_tuple("clamav-1.5.4") == (1, 5, 4)
    assert parse_version_tuple("1.5.4") == (1, 5, 4)
    assert parse_version_tuple("0.103.2") == (0, 103, 2)
    assert parse_version_tuple("1.6.0-rc1") == (1, 6, 0)
    assert parse_version_tuple("Unknown") == (0, 0, 0)
    assert parse_version_tuple("1.5.5") > parse_version_tuple("1.5.4")
    assert parse_version_tuple("1.10.0") > parse_version_tuple("1.9.9")


def test_apply_zip_update_direct_preserves_configs_and_db():
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_dir = os.path.join(tmp_dir, "clamav_install")
        os.makedirs(target_dir, exist_ok=True)

        # Existing user config files and database file
        existing_conf = os.path.join(target_dir, "freshclam.conf")
        with open(existing_conf, "w", encoding="utf-8") as f:
            f.write("# USER CUSTOM CONFIG PRESERVED")

        db_dir = os.path.join(target_dir, "database")
        os.makedirs(db_dir, exist_ok=True)
        db_file = os.path.join(db_dir, "daily.cvd")
        with open(db_file, "w", encoding="utf-8") as f:
            f.write("MOCK CVD SIGNATURE DATA")

        # Create mock ClamAV zip with a top-level directory
        zip_path = os.path.join(tmp_dir, "clamav-mock.win.x64.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("clamav-mock.win.x64/clamscan.exe", b"MOCK_CLAMSCAN_BIN")
            zf.writestr("clamav-mock.win.x64/freshclam.exe", b"MOCK_FRESHCLAM_BIN")
            zf.writestr("clamav-mock.win.x64/freshclam.conf", b"# OVERWRITE ATTEMPT")
            zf.writestr("clamav-mock.win.x64/database/daily.cvd", b"OVERWRITE ATTEMPT")

        success, msg, count = ClamAVBinaryUpdater.apply_zip_update_direct(zip_path, target_dir)
        assert success is True
        assert count >= 2

        # Check binaries extracted
        assert os.path.isfile(os.path.join(target_dir, "clamscan.exe"))
        with open(os.path.join(target_dir, "clamscan.exe"), "rb") as f:
            assert f.read() == b"MOCK_CLAMSCAN_BIN"

        assert os.path.isfile(os.path.join(target_dir, "freshclam.exe"))

        # Verify existing user config was preserved and NOT overwritten
        with open(existing_conf, "r", encoding="utf-8") as f:
            assert f.read() == "# USER CUSTOM CONFIG PRESERVED"

        # Verify existing database file was preserved
        with open(db_file, "r", encoding="utf-8") as f:
            assert f.read() == "MOCK CVD SIGNATURE DATA"


def test_check_for_updates_mocked(tmp_path):
    cm = ConfigManager(config_path=str(tmp_path / "config.json"))
    engine = ClamAVEngine(cm.config)
    engine.engine_version = "ClamAV 1.5.0"

    updater = ClamAVBinaryUpdater(cm, engine)

    mock_response_data = {
        "tag_name": "clamav-1.5.4",
        "name": "ClamAV 1.5.4",
        "html_url": "https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4",
        "published_at": "2026-08-01T00:00:00Z",
        "assets": [
            {
                "name": "clamav-1.5.4.win.x64.zip",
                "size": 225000000,
                "browser_download_url": "https://example.com/clamav-1.5.4.win.x64.zip",
                "content_type": "application/zip",
            },
            {
                "name": "clamav-1.5.4.win.x64.msi",
                "size": 224000000,
                "browser_download_url": "https://example.com/clamav-1.5.4.win.x64.msi",
                "content_type": "application/octet-stream",
            },
        ],
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_response_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        success, msg, info = updater.check_for_updates()
        assert success is True
        assert info is not None
        assert info.version == "1.5.4"
        assert info.is_newer is True
        assert info.zip_asset is not None
        assert info.zip_asset.name == "clamav-1.5.4.win.x64.zip"
        assert info.msi_asset is not None
        assert info.msi_asset.name == "clamav-1.5.4.win.x64.msi"


def test_parse_definition_version_distinguishes_daily_and_bytecode():
    from app.core.updater import UpdateManager
    cm = MagicMock()
    eng = MagicMock()
    eng.engine_version = "ClamAV 1.5.4/28155/Fri Oct 16 11:54:17 2026"
    upd = UpdateManager(cm, eng)

    # Output containing daily, main, and bytecode
    sample_out = (
        "ClamAV update process started at Fri Oct 16 12:02:32 2026\n"
        "Fri Oct 16 12:02:32 2026 -> daily.cld database is up-to-date (version: 28155, sigs: 355765, f-level: 90, builder: svc.clamav-publisher)\n"
        "Fri Oct 16 12:02:32 2026 -> main.cvd database is up-to-date (version: 63, sigs: 3287027, f-level: 90, builder: tomjudge)\n"
        "Fri Oct 16 12:02:32 2026 -> bytecode.cvd database is up-to-date (version: 339, sigs: 80, f-level: 90, builder: nrandolp)\n"
    )
    result = upd.parse_definition_version(sample_out)
    assert result == "Daily ver. 28155"

    # Output without daily in text falls back to engine version
    fallback_out = "bytecode.cvd (version: 339)"
    result_fallback = upd.parse_definition_version(fallback_out)
    assert result_fallback == "Daily ver. 28155"
