import os
import tempfile
import pytest

from app.core.config import ConfigManager
from app.core.config_generator import ClamAVConfigGenerator
from app.core.engine import ClamAVEngine


def test_generate_configs_direct_in_temp_dir():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a mock certs directory to verify certs directive
        certs_dir = os.path.join(tmp_dir, "certs")
        os.makedirs(certs_dir, exist_ok=True)

        success, msg, files = ClamAVConfigGenerator.generate_configs_direct(tmp_dir)
        assert success is True
        assert len(files) == 2

        freshclam_conf = os.path.join(tmp_dir, "freshclam.conf")
        clamd_conf = os.path.join(tmp_dir, "clamd.conf")
        db_dir = os.path.join(tmp_dir, "database")

        assert os.path.isfile(freshclam_conf)
        assert os.path.isfile(clamd_conf)
        assert os.path.isdir(db_dir)

        # Check freshclam.conf content
        with open(freshclam_conf, "r", encoding="utf-8") as f:
            fc_content = f.read()

        assert "Example" not in fc_content
        assert f'DatabaseDirectory "{db_dir}"' in fc_content
        assert f'CVDCertsDirectory "{certs_dir}"' in fc_content
        assert "DatabaseMirror database.clamav.net" in fc_content
        assert "DNSDatabaseInfo current.cvd.clamav.net" in fc_content

        # Check clamd.conf content
        with open(clamd_conf, "r", encoding="utf-8") as f:
            cd_content = f.read()

        assert "Example" not in cd_content
        assert f'DatabaseDirectory "{db_dir}"' in cd_content
        assert "TCPSocket 3310" in cd_content
        assert "TCPAddr 127.0.0.1" in cd_content
        assert "MaxConnectionQueueLength" in cd_content


def test_generate_configs_invalid_dir():
    success, msg, files = ClamAVConfigGenerator.generate_configs_direct("Z:\\NonExistentPath_TinyAV_12345")
    assert success is False
    assert len(files) == 0


def test_high_level_generate_configs(tmp_path):
    config_file = str(tmp_path / "config.json")
    cm = ConfigManager(config_path=config_file)
    engine = ClamAVEngine(cm.config)

    clamav_dir = str(tmp_path / "clamav_mock")
    os.makedirs(clamav_dir, exist_ok=True)

    success, msg, files = ClamAVConfigGenerator.generate_configs(
        clamav_dir=clamav_dir,
        config_manager=cm,
        engine=engine,
    )
    assert success is True
    # Ensure config was updated and persisted
    assert cm.config.clamav_bin_dir == os.path.normpath(clamav_dir)
    assert os.path.isfile(os.path.join(clamav_dir, "freshclam.conf"))
    assert os.path.isfile(os.path.join(clamav_dir, "clamd.conf"))
    assert os.path.isdir(os.path.join(clamav_dir, "database"))
