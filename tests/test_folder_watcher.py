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


def test_folder_watcher_trailing_edge_debounce_and_clean_notification():
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        os.makedirs(watched_dir, exist_ok=True)

        cfg = AppConfig(
            watched_directories=[watched_dir],
            realtime_watch_enabled=True,
            notify_on_clean=True,
        )
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        engine.scan_single_file.return_value = ("OK", None, None)
        quarantine_mgr = MagicMock(spec=QuarantineManager)

        clean_scans = []
        started_scans = []
        watcher = RealtimeFolderWatcher(
            cfg_mgr,
            engine,
            quarantine_mgr,
            on_scan_clean=lambda p: clean_scans.append(p),
            on_scan_start=lambda p: started_scans.append(p),
            debounce_window=0.3,
        )

        test_file = os.path.join(watched_dir, "clean_download.zip")

        # Simulate progressive download chunks triggering multiple modify events
        with open(test_file, "wb") as f:
            f.write(b"chunk1")
        watcher.queue_scan(test_file)
        time.sleep(0.1)

        with open(test_file, "ab") as f:
            f.write(b"chunk2")
        watcher.queue_scan(test_file)
        time.sleep(0.1)

        with open(test_file, "ab") as f:
            f.write(b"chunk3-final")
        watcher.queue_scan(test_file)

        # Wait for trailing edge quiet period (0.3s) + settle + scan
        time.sleep(0.9)
        watcher.stop()

        # Engine should have been called exactly once after writes settled
        assert engine.scan_single_file.call_count == 1
        assert len(started_scans) == 1
        assert len(clean_scans) == 1
        assert clean_scans[0] == test_file


def test_folder_watcher_recursive_and_ads_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        sibling_dir = os.path.join(tmpdir, "Downloads_Backup")
        sub_dir = os.path.join(watched_dir, "Torrents", "Software")
        os.makedirs(sub_dir, exist_ok=True)
        os.makedirs(sibling_dir, exist_ok=True)

        cfg = AppConfig(watched_directories=[watched_dir])
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        watcher = RealtimeFolderWatcher(cfg_mgr, MagicMock(), MagicMock())

        # Subdirectory file should be watched
        nested_file = os.path.join(sub_dir, "installer.exe")
        assert watcher.is_path_watched(nested_file) is True

        # Sibling directory starting with same prefix should NOT be watched
        sibling_file = os.path.join(sibling_dir, "file.exe")
        assert watcher.is_path_watched(sibling_file) is False

        # Alternate Data Stream (Zone.Identifier) should be recognized as watched
        ads_path = os.path.join(watched_dir, "installer.exe:Zone.Identifier")
        assert watcher.is_path_watched(ads_path) is True


def test_folder_watcher_batch_extraction_burst():
    from app.core.engine import ScanSummary

    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        extracted_folder = os.path.join(watched_dir, "extracted_project")
        os.makedirs(extracted_folder, exist_ok=True)

        cfg = AppConfig(watched_directories=[watched_dir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        engine.scan_single_file.return_value = ("OK", None, None)
        # Mock scan_files returning clean summary for batch
        def mock_scan_files(file_paths=None, *args, **kwargs):
            paths = file_paths or []
            s = ScanSummary()
            s.scanned_files = len(paths)
            return s
        engine.scan_files.side_effect = mock_scan_files

        quarantine_mgr = MagicMock(spec=QuarantineManager)

        batch_clean_events = []
        watcher = RealtimeFolderWatcher(
            cfg_mgr,
            engine,
            quarantine_mgr,
            on_batch_clean=lambda count, sample: batch_clean_events.append((count, sample)),
            debounce_window=0.2,
        )
        watcher.start()

        # Simulate extracting 10 files in rapid burst
        created_paths = []
        for i in range(10):
            p = os.path.join(extracted_folder, f"file_{i}.txt")
            with open(p, "wb") as f:
                f.write(f"content {i}".encode("utf-8"))
            created_paths.append(p)
            watcher.queue_scan(p)

        # Allow worker loop to process settled batch
        time.sleep(1.0)
        watcher.stop()

        # Should have scanned files via batch scan_files, avoiding 10 separate clamscan process spawns
        assert engine.scan_files.call_count >= 1
        assert len(batch_clean_events) >= 1
        total_scanned = sum(count for count, _ in batch_clean_events)
        assert total_scanned == 10


def test_folder_watcher_queue_during_active_scan():
    """Verify that files arriving while an existing scan is underway are not dropped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        os.makedirs(watched_dir, exist_ok=True)

        cfg = AppConfig(watched_directories=[watched_dir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        scanned_paths = []
        engine = MagicMock(spec=ClamAVEngine)

        def slow_scan(path):
            scanned_paths.append(path)
            time.sleep(0.3)  # Simulate active scan duration
            return ("OK", None, None)

        def mock_scan_files(file_paths=None, *args, **kwargs):
            paths = file_paths or []
            scanned_paths.extend(paths)
            s = MagicMock()
            s.scanned_files = len(paths)
            return s

        engine.scan_single_file.side_effect = slow_scan
        engine.scan_files.side_effect = mock_scan_files
        quarantine_mgr = MagicMock(spec=QuarantineManager)

        progress_events = []
        complete_events = []

        watcher = RealtimeFolderWatcher(
            cfg_mgr,
            engine,
            quarantine_mgr,
            on_queue_progress=lambda d, t, p: progress_events.append((d, t, p)),
            on_queue_complete=lambda t, th: complete_events.append((t, th)),
            debounce_window=0.1,
            cooldown_window=0.5,
        )
        watcher.start()

        # 1. Enqueue file 1
        f1 = os.path.join(watched_dir, "file1.exe")
        with open(f1, "wb") as f:
            f.write(b"content1")
        watcher.queue_scan(f1)

        # Wait briefly for file1 to start scanning
        time.sleep(0.18)

        # 2. While file 1 is actively scanning, enqueue file 2 and file 3
        f2 = os.path.join(watched_dir, "file2.exe")
        with open(f2, "wb") as f:
            f.write(b"content2")
        f3 = os.path.join(watched_dir, "file3.exe")
        with open(f3, "wb") as f:
            f.write(b"content3")

        watcher.queue_scan(f2)
        watcher.queue_scan(f3)

        # Allow worker loop to complete all queued items
        time.sleep(1.2)
        watcher.stop()

        # All 3 files must have been scanned without any drops
        norm_scanned = [os.path.normcase(os.path.abspath(p)) for p in scanned_paths]
        assert os.path.normcase(os.path.abspath(f1)) in norm_scanned
        assert os.path.normcase(os.path.abspath(f2)) in norm_scanned
        assert os.path.normcase(os.path.abspath(f3)) in norm_scanned
        assert len(complete_events) >= 1


def test_folder_watcher_locked_file_retry():
    """Verify that a locked file (e.g. browser still writing) is not dropped from the queue."""
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        os.makedirs(watched_dir, exist_ok=True)

        cfg = AppConfig(watched_directories=[watched_dir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        engine.scan_single_file.return_value = ("OK", None, None)
        quarantine_mgr = MagicMock(spec=QuarantineManager)

        watcher = RealtimeFolderWatcher(
            cfg_mgr,
            engine,
            quarantine_mgr,
            debounce_window=0.1,
        )

        test_file = os.path.join(watched_dir, "download.bin")
        with open(test_file, "wb") as f:
            f.write(b"data")

        # Simulate lock: first call returns False, second call returns True
        call_count = {"count": 0}
        orig_readable = watcher._is_file_readable

        def mock_is_readable(path):
            call_count["count"] += 1
            if call_count["count"] == 1:
                return False  # Locked on first check
            return orig_readable(path)

        watcher._is_file_readable = mock_is_readable
        watcher.start()
        watcher.queue_scan(test_file)

        # Wait for retry loop
        time.sleep(1.2)
        watcher.stop()

        # Should have retried and successfully scanned
        assert call_count["count"] >= 2
        engine.scan_single_file.assert_called_once()


def test_folder_watcher_queue_directory_recursive():
    """Verify recursive directory walking queues all valid nested files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        watched_dir = os.path.join(tmpdir, "Downloads")
        nested_dir = os.path.join(watched_dir, "unzipped", "sub")
        os.makedirs(nested_dir, exist_ok=True)

        f1 = os.path.join(watched_dir, "unzipped", "root_file.exe")
        f2 = os.path.join(nested_dir, "deep_file.dll")
        with open(f1, "wb") as f:
            f.write(b"1")
        with open(f2, "wb") as f:
            f.write(b"2")

        cfg = AppConfig(watched_directories=[watched_dir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        quarantine_mgr = MagicMock(spec=QuarantineManager)

        watcher = RealtimeFolderWatcher(cfg_mgr, engine, quarantine_mgr)
        queued = []
        watcher.queue_scan = lambda p: queued.append(p)

        watcher.queue_directory(os.path.join(watched_dir, "unzipped"))

        assert len(queued) == 2
        norm_queued = [os.path.normcase(os.path.abspath(p)) for p in queued]
        assert os.path.normcase(os.path.abspath(f1)) in norm_queued
        assert os.path.normcase(os.path.abspath(f2)) in norm_queued


def test_watched_progress_overlay_ui():
    """Test WatchedProgressOverlay widget lifecycle, progress updates, and completion text."""
    import tkinter as tk
    from app.ui.watched_progress_overlay import WatchedProgressOverlay

    root = tk.Tk()
    root.withdraw()
    try:
        overlay = WatchedProgressOverlay(root)
        # Initially hidden
        assert overlay._is_visible is False

        # Update progress
        overlay.update_progress(2, 5, "C:\\Users\\Downloads\\installer.exe")
        overlay.update_idletasks()
        assert overlay._is_visible is True
        assert overlay.progress_bar["value"] == 40
        assert "installer.exe" in overlay.file_label.cget("text")
        assert overlay.count_label.cget("text") == "40%"

        # Complete clean
        overlay.on_completed(5, 0)
        overlay.update_idletasks()
        assert overlay.progress_bar["value"] == 100
        assert "clean" in overlay.file_label.cget("text").lower()

        # Hide
        overlay.hide()
        assert overlay._is_visible is False
    finally:
        root.destroy()


