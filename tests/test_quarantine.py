import os
import tempfile
import pytest

from app.core.quarantine import QuarantineManager

def test_quarantine_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        quarantine_dir = os.path.join(tmpdir, "Quarantine")
        mgr = QuarantineManager(quarantine_dir=quarantine_dir)

        # 1. Create a dummy test file
        test_file = os.path.join(tmpdir, "malicious_sample.txt")
        content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with open(test_file, "w") as f:
            f.write(content)

        assert os.path.exists(test_file)

        # 2. Quarantine it
        threat_name = "EICAR-Test-Signature"
        item = mgr.quarantine_file(test_file, threat_name)
        assert item is not None
        assert item.threat_name == threat_name
        assert item.original_path == test_file
        # Original file must no longer exist in original path
        assert not os.path.exists(test_file)

        # Check file in quarantine
        stored_file = os.path.join(quarantine_dir, item.quarantine_filename)
        assert os.path.exists(stored_file)
        meta_file = os.path.join(quarantine_dir, f"{item.id}.json")
        assert os.path.exists(meta_file)

        # 3. List quarantined items
        items = mgr.list_items()
        assert len(items) == 1
        assert items[0].id == item.id
        assert items[0].threat_name == threat_name

        # 4. Restore the item
        restored = mgr.restore_item(item.id)
        assert restored is True
        assert os.path.exists(test_file)
        assert not os.path.exists(stored_file)
        assert not os.path.exists(meta_file)

        # Verify content intact
        with open(test_file, "r") as f:
            assert f.read() == content

        # 5. Quarantine again and permanently delete
        item2 = mgr.quarantine_file(test_file, threat_name)
        assert item2 is not None
        assert os.path.exists(os.path.join(quarantine_dir, item2.quarantine_filename))

        deleted = mgr.delete_item(item2.id)
        assert deleted is True
        assert not os.path.exists(os.path.join(quarantine_dir, item2.quarantine_filename))
        assert not os.path.exists(os.path.join(quarantine_dir, f"{item2.id}.json"))
        assert len(mgr.list_items()) == 0

def test_quarantine_restore_collision():
    with tempfile.TemporaryDirectory() as tmpdir:
        quarantine_dir = os.path.join(tmpdir, "Quarantine")
        mgr = QuarantineManager(quarantine_dir=quarantine_dir)

        test_file = os.path.join(tmpdir, "sample.txt")
        with open(test_file, "w") as f:
            f.write("original infected payload")

        item = mgr.quarantine_file(test_file, "Threat.A")
        assert item is not None

        # Re-create a new file at test_file before restoring
        with open(test_file, "w") as f:
            f.write("new legitimate file")

        # Restoring should not overwrite new file, but save with _restored suffix
        assert mgr.restore_item(item.id) is True
        assert os.path.exists(test_file)
        with open(test_file, "r") as f:
            assert f.read() == "new legitimate file"

        restored_file = os.path.join(tmpdir, "sample_restored.txt")
        assert os.path.exists(restored_file)
        with open(restored_file, "r") as f:
            assert f.read() == "original infected payload"


def test_quarantine_restore_multiple_collisions():
    with tempfile.TemporaryDirectory() as tmpdir:
        quarantine_dir = os.path.join(tmpdir, "Quarantine")
        mgr = QuarantineManager(quarantine_dir=quarantine_dir)

        test_file = os.path.join(tmpdir, "sample.txt")
        with open(test_file, "w") as f:
            f.write("payload 1")
        item1 = mgr.quarantine_file(test_file, "Threat.A")

        # Create sample.txt and sample_restored.txt already present
        with open(test_file, "w") as f:
            f.write("original occupied")
        with open(os.path.join(tmpdir, "sample_restored.txt"), "w") as f:
            f.write("restored occupied")

        assert mgr.restore_item(item1.id) is True
        expected_candidate = os.path.join(tmpdir, "sample_restored_1.txt")
        assert os.path.exists(expected_candidate)
        with open(expected_candidate, "r") as f:
            assert f.read() == "payload 1"
