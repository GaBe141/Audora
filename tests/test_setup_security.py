"""Security tests for setup-generated credential files."""

import os

import pytest

from scripts.setup import EnhancedMusicDiscoverySetup


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not enforced on Windows")
def test_private_writer_creates_owner_only_files(tmp_path):
    setup = object.__new__(EnhancedMusicDiscoverySetup)
    target = tmp_path / "config" / "notification_config.json"

    setup._write_private_text(target, '{"secret": "placeholder"}\n')

    assert oct(target.stat().st_mode)[-3:] == "600"
    assert target.read_text(encoding="utf-8") == '{"secret": "placeholder"}\n'


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not enforced on Windows")
def test_private_writer_tightens_existing_file_permissions(tmp_path):
    setup = object.__new__(EnhancedMusicDiscoverySetup)
    target = tmp_path / ".env.enhanced"
    target.write_text("old=value\n", encoding="utf-8")
    target.chmod(0o644)

    setup._write_private_text(target, "new=value\n")

    assert oct(target.stat().st_mode)[-3:] == "600"
    assert target.read_text(encoding="utf-8") == "new=value\n"
