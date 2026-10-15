import json
import os
import tempfile
import pytest

from app.core.config import AppConfig, ConfigManager

def test_default_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = os.path.join(tmpdir, "config.json")
        mgr = ConfigManager(config_path=cfg_file)

        assert mgr.config.update_interval_hours == 4
        assert mgr.config.prefer_clamd is False
        assert mgr.config.clamd_host == "127.0.0.1"
        assert mgr.config.clamd_port == 3310
        assert os.path.exists(cfg_file)

def test_update_and_save_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = os.path.join(tmpdir, "config.json")
        mgr = ConfigManager(config_path=cfg_file)

        mgr.update(
            update_interval_hours=6,
            clamav_bin_dir=r"C:\Custom\ClamAV",
            prefer_clamd=True,
            remembered_drives={"0x1234": "auto_scan"},
            realtime_watch_enabled=True,
            watched_directories=[r"C:\Downloads", r"C:\Desktop"],
            realtime_auto_quarantine=True,
        )

        # Reload from disk
        new_mgr = ConfigManager(config_path=cfg_file)
        assert new_mgr.config.update_interval_hours == 6
        assert new_mgr.config.clamav_bin_dir == r"C:\Custom\ClamAV"
        assert new_mgr.config.prefer_clamd is True
        assert new_mgr.config.remembered_drives == {"0x1234": "auto_scan"}
        assert new_mgr.config.realtime_watch_enabled is True
        assert new_mgr.config.watched_directories == [r"C:\Downloads", r"C:\Desktop"]
        assert new_mgr.config.realtime_auto_quarantine is True

def test_corrupted_config_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_file = os.path.join(tmpdir, "config.json")
        with open(cfg_file, "w") as f:
            f.write("invalid json{{{")

        mgr = ConfigManager(config_path=cfg_file)
        # Should fall back to default values without raising
        assert mgr.config.update_interval_hours == 4
        assert mgr.config.clamd_port == 3310
