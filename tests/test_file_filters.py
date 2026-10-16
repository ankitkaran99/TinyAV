import os
import tempfile
from unittest.mock import MagicMock
import pytest

from app.core.config import AppConfig, ConfigManager
from app.core.engine import ClamAVEngine
from app.core.file_filters import should_skip_dir, should_skip_file
from app.core.folder_watcher import RealtimeFolderWatcher
from app.core.quarantine import QuarantineManager


def test_should_skip_desktop_ini():
    assert should_skip_file("desktop.ini") is True
    assert should_skip_file(r"C:\Users\User\Downloads\desktop.ini") is True
    assert should_skip_file(r"C:\Storage\desktop.ini:Zone.Identifier") is True
    assert should_skip_file(r"/home/user/desktop.ini") is True
    assert should_skip_file("DESKTOP.INI") is True


def test_should_skip_thumbs_db():
    assert should_skip_file("thumbs.db") is True
    assert should_skip_file(r"C:\Pictures\Thumbs.db") is True
    assert should_skip_file("ehthumbs.db") is True
    assert should_skip_file(".DS_Store") is True


def test_should_skip_temp_and_lock_files():
    assert should_skip_file("download.crdownload") is True
    assert should_skip_file("archive.part") is True
    assert should_skip_file("data.tmp") is True
    assert should_skip_file("~$Document.docx") is True
    assert should_skip_file(r"C:\Docs\~$Proposal.xlsx") is True


def test_should_not_skip_legitimate_files():
    assert should_skip_file("test.exe") is False
    assert should_skip_file("document.pdf") is False
    assert should_skip_file("script.py") is False
    assert should_skip_file("desktop_app.exe") is False
    assert should_skip_file("iniciator.bat") is False


def test_should_skip_dir():
    assert should_skip_dir(r"C:\Repo\.git") is True
    assert should_skip_dir(r"C:\Storage\$Recycle.Bin") is True
    assert should_skip_dir(r"C:\System Volume Information") is True
    assert should_skip_dir("node_modules") is True
    assert should_skip_dir("Downloads") is False
    assert should_skip_dir("Documents") is False


def test_folder_watcher_ignores_desktop_ini():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = AppConfig(watched_directories=[tmpdir], realtime_watch_enabled=True)
        cfg_mgr = ConfigManager()
        cfg_mgr.config = cfg

        engine = MagicMock(spec=ClamAVEngine)
        quarantine = MagicMock(spec=QuarantineManager)

        watcher = RealtimeFolderWatcher(cfg_mgr, engine, quarantine)

        desktop_ini = os.path.join(tmpdir, "desktop.ini")
        thumbs_db = os.path.join(tmpdir, "thumbs.db")

        # Must not be watched
        assert watcher.is_path_watched(desktop_ini) is False
        assert watcher.is_path_watched(thumbs_db) is False

        # queue_scan must ignore desktop.ini
        watcher.queue_scan(desktop_ini)
        watcher.queue_scan(thumbs_db)

        assert len(watcher._queue) == 0


def test_engine_skips_desktop_ini():
    cfg = AppConfig()
    engine = ClamAVEngine(cfg)

    # scan_single_file returns OK immediately for desktop.ini
    st, threat, err = engine.scan_single_file(r"C:\Windows\desktop.ini")
    assert st == "OK"
    assert threat is None
    assert err is None

    # scan_files filters out desktop.ini
    summary = engine.scan_files([r"C:\Windows\desktop.ini", r"C:\Folder\thumbs.db"])
    assert summary.scanned_files == 0
    assert summary.infected_files == 0
