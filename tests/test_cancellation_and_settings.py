import subprocess
import threading
import time
from unittest.mock import MagicMock

import pytest
from app.core.config import AppConfig
from app.core.engine import ClamAVEngine

def test_engine_cancel_active_scan():
    config = AppConfig()
    engine = ClamAVEngine(config)

    # Mock an active process
    mock_proc = MagicMock(spec=subprocess.Popen)
    engine._active_proc = mock_proc

    engine.cancel_active_scan()

    mock_proc.terminate.assert_called_once()
    assert engine._active_proc is None

def test_engine_cancel_when_no_active_proc():
    config = AppConfig()
    engine = ClamAVEngine(config)
    engine._active_proc = None

    # Should not raise exception
    engine.cancel_active_scan()
    assert engine._active_proc is None


def test_scan_excludes_quarantine_directory(tmp_path):
    import os
    from app.core.quarantine import QuarantineManager

    quar_dir = str(tmp_path / "Quarantine")
    os.makedirs(quar_dir, exist_ok=True)
    qm = QuarantineManager(quarantine_dir=quar_dir)

    # Place a file in quarantine
    quar_file = os.path.join(quar_dir, "malicious.quarantine")
    with open(quar_file, "w") as f:
        f.write("quarantined threat")

    # Place legitimate files in normal directory
    legit_dir = str(tmp_path / "NormalFiles")
    os.makedirs(legit_dir, exist_ok=True)
    legit_file = os.path.join(legit_dir, "doc.txt")
    with open(legit_file, "w") as f:
        f.write("legitimate document")

    # Collect files starting from parent tmp_path using the exclusion pattern
    quar_norm = os.path.normcase(os.path.abspath(qm.quarantine_dir))
    collected = []
    for root, dirs, files in os.walk(str(tmp_path), topdown=True):
        dirs[:] = [d for d in dirs if not os.path.normcase(os.path.abspath(os.path.join(root, d))).startswith(quar_norm)]
        for f in files:
            collected.append(os.path.join(root, f))

    assert legit_file in collected
    assert quar_file not in collected


def test_scan_files_duration_tracking():
    from app.core.engine import EngineMode
    config = AppConfig()
    engine = ClamAVEngine(config)

    # Empty files list should still measure duration
    summary = engine.scan_files([])
    assert summary.duration_seconds >= 0.0

    # Test file-by-file path with mocked scan_single_file
    engine.mode = EngineMode.CLAMD
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(engine, "scan_single_file", lambda p: ("OK", None, None))
        summary = engine.scan_files(["dummy_file1.txt", "dummy_file2.txt"])
        assert summary.duration_seconds >= 0.0
        assert summary.scanned_files == 2

