import os
import pytest
from app.core.process_scanner import ProcessFileCollector

def test_collect_process_files():
    # Should run on current machine and return non-empty list of unique paths
    paths, mapping = ProcessFileCollector.collect_process_files()
    assert isinstance(paths, list)
    assert isinstance(mapping, dict)
    assert len(paths) > 0

    # Ensure python executable running this test is among collected paths
    current_python = os.path.normcase(os.path.abspath(os.sys.executable))
    assert current_python in paths

    # Ensure all collected paths actually exist on disk
    for p in paths[:20]:  # Sample first 20
        assert os.path.isfile(p)
