import pytest
from app.core.config import AppConfig
from app.core.engine import ClamAVEngine, EngineMode

def test_parse_clamscan_line_ok():
    line = r"C:\path\to\document.pdf: OK"
    status, path, threat, err = ClamAVEngine.parse_clamscan_line(line)
    assert status == "OK"
    assert path == r"C:\path\to\document.pdf"
    assert threat is None
    assert err is None

def test_parse_clamscan_line_found():
    line = r"C:\Downloads\eicar.com.txt: Win.Test.EICAR_HDB-1 FOUND"
    status, path, threat, err = ClamAVEngine.parse_clamscan_line(line)
    assert status == "FOUND"
    assert path == r"C:\Downloads\eicar.com.txt"
    assert threat == "Win.Test.EICAR_HDB-1"
    assert err is None

def test_parse_clamscan_line_error():
    line = r"C:\System Volume Information\tracking.log: Can't open file ERROR"
    status, path, threat, err = ClamAVEngine.parse_clamscan_line(line)
    assert status == "ERROR"
    assert path == r"C:\System Volume Information\tracking.log"
    assert threat is None
    assert err == "Can't open file"

def test_parse_clamscan_unrelated_lines():
    for line in [
        "----------- SCAN SUMMARY -----------",
        "Infected files: 1",
        "Total errors: 0",
        "Time: 0.054 sec (0 m 0 s)",
        "",
        "   ",
    ]:
        status, path, threat, err = ClamAVEngine.parse_clamscan_line(line)
        assert status is None
        assert path is None
        assert threat is None
        assert err is None

def test_engine_mode_unavailable_when_no_binaries(monkeypatch):
    config = AppConfig(prefer_clamd=False)
    engine = ClamAVEngine(config)
    # Force find_binary to return None
    monkeypatch.setattr(engine, "find_binary", lambda name: None)
    mode = engine.refresh_engine()
    assert mode == EngineMode.UNAVAILABLE
    assert engine.engine_version == "Not detected"
