"""Security tests for report file path handling."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_main_app_report_rejects_parent_traversal() -> None:
    """Main app should not allow writing reports outside data/."""
    with pytest.raises(ValueError, match="data directory"):
        ComprehensiveMusicDiscoveryApp._resolve_report_path("../outside.json")


def test_main_app_report_default_stays_in_data_dir() -> None:
    """Default report path should resolve into project data dir."""
    resolved = ComprehensiveMusicDiscoveryApp._resolve_report_path("report.json")
    data_dir = (Path(__file__).resolve().parent.parent / "data").resolve()
    assert data_dir in [resolved, *resolved.parents]
    assert resolved.suffix == ".json"


def test_social_engine_report_rejects_parent_traversal() -> None:
    """Social engine should reject traversal outside data directory."""
    engine = SocialMusicDiscoveryEngine(config={})
    with pytest.raises(ValueError, match="data directory"):
        engine._resolve_report_path("../outside.json")


def test_social_engine_report_default_stays_in_data_dir() -> None:
    """Social engine default path should remain in data directory."""
    engine = SocialMusicDiscoveryEngine(config={})
    resolved = engine._resolve_report_path(None)
    data_dir = Path("data").resolve()
    assert data_dir in [resolved, *resolved.parents]
