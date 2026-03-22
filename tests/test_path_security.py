"""Path traversal protections for report and export paths."""

from pathlib import Path

import pytest

from core.utils import resolve_path_within_base
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_resolve_path_within_base_blocks_traversal(tmp_path):
    base_dir = tmp_path / "data"
    base_dir.mkdir()

    with pytest.raises(ValueError, match="Path traversal blocked"):
        resolve_path_within_base("../outside.json", base_dir)


def test_social_engine_save_report_blocks_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine.__new__(SocialMusicDiscoveryEngine)

    with pytest.raises(ValueError, match="Path traversal blocked"):
        engine.save_discovery_report({"status": "ok"}, "../../outside.json")
