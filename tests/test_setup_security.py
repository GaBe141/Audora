"""Security tests for setup-created credential-bearing files."""

import os

import pytest

from scripts.setup import EnhancedMusicDiscoverySetup


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")


def test_setup_writes_config_files_with_owner_only_permissions(tmp_path):
    setup = EnhancedMusicDiscoverySetup()
    setup.project_root = tmp_path
    setup.config_dir = tmp_path / "config"
    setup.config_dir.mkdir()

    assert setup.setup_configuration() is True

    for config_path in setup.config_dir.glob("*.json"):
        mode = config_path.stat().st_mode & 0o777
        assert mode == 0o600


def test_setup_writes_env_file_with_owner_only_permissions(tmp_path):
    setup = EnhancedMusicDiscoverySetup()
    setup.project_root = tmp_path

    assert setup.setup_environment() is True

    env_path = tmp_path / ".env.enhanced"
    assert env_path.exists()
    assert env_path.stat().st_mode & 0o777 == 0o600
