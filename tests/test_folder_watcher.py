import os
import tempfile
import time
from unittest.mock import MagicMock

import pytest
from app.core.config import AppConfig, ConfigManager
from app.core.engine import ClamAVEngine
from app.core.folder_watcher import RealtimeFolderWatcher
from app.core.quarantine import QuarantineManager

def test_folder_watcher_temp_file_filter():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = AppConfig(watched_directories=[tmpdir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        quarantine = MagicMock(spec=QuarantineManager)

        watcher = RealtimeFolderWatcher(cfg_mgr, engine, quarantine)
        
        # Calling queue_scan with temporary extension should be ignored immediately
        watcher.queue_scan(os.path.join(tmpdir, "test.crdownload"))
        watcher.queue_scan(os.path.join(tmpdir, "archive.part"))
        watcher.queue_scan(os.path.join(tmpdir, "data.tmp"))

        time.sleep(0.1)
        engine.scan_single_file.assert_not_called()

def test_folder_watcher_scan_and_auto_quarantine():
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        quarantine_dir = os.path.join(tmpdir, "Quarantine")
        os.makedirs(watched_dir, exist_ok=True)
        os.makedirs(quarantine_dir, exist_ok=True)

        cfg = AppConfig(
            watched_directories=[watched_dir],
            realtime_watch_enabled=True,
            realtime_auto_quarantine=True,
            quarantine_dir=quarantine_dir,
        )
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        # Mock engine to report malicious detection
        engine.scan_single_file.return_value = ("FOUND", "Win.Test.EICAR", None)

        quarantine_mgr = QuarantineManager(quarantine_dir=quarantine_dir)

        threat_detected = []
        def on_threat(path, threat, auto_quar):
            threat_detected.append((path, threat, auto_quar))

        watcher = RealtimeFolderWatcher(
            cfg_mgr,
            engine,
            quarantine_mgr,
            on_threat_detected=on_threat,
        )
        watcher.start()

        # Create a new infected file in watched directory
        infected_path = os.path.join(watched_dir, "malicious.exe")
        with open(infected_path, "wb") as f:
            f.write(b"EICAR-TEST-CONTENT")

        # Manually trigger queue_scan or let watcher detect
        watcher.queue_scan(infected_path)

        # Wait for worker thread
        time.sleep(1.2)
        watcher.stop()

        # Threat callback should have been called
        assert len(threat_detected) > 0
        path, threat, auto_quar = threat_detected[0]
        assert threat == "Win.Test.EICAR"
        assert auto_quar is True
        # Original file should have been quarantined
        assert not os.path.exists(infected_path)

def test_folder_watcher_quarantine_exclusion():
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        quarantine_dir = os.path.join(tmpdir, "Quarantine")
        os.makedirs(watched_dir, exist_ok=True)
        os.makedirs(quarantine_dir, exist_ok=True)

        cfg = AppConfig(
            watched_directories=[watched_dir],
            quarantine_dir=quarantine_dir,
        )
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        quarantine_mgr = QuarantineManager(quarantine_dir=quarantine_dir)

        watcher = RealtimeFolderWatcher(cfg_mgr, engine, quarantine_mgr)

        # File in watched directory is watched
        valid_file = os.path.join(watched_dir, "test.exe")
        assert watcher.is_path_watched(valid_file) is True

        # File in quarantine directory is excluded
        quar_file = os.path.join(quarantine_dir, "malware.quarantine")
        assert watcher.is_path_watched(quar_file) is False

        # File outside watched directories is excluded
        outside_file = os.path.join(tmpdir, "other.exe")
        assert watcher.is_path_watched(outside_file) is False

        # Temp file is excluded
        temp_file = os.path.join(watched_dir, "download.crdownload")
        assert watcher.is_path_watched(temp_file) is False
