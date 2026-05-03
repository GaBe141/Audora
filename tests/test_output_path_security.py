"""Security tests for output path confinement."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import resolve_safe_output_path
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_resolve_safe_output_path_rejects_parent_traversal():
    with pytest.raises(ValueError, match="Output path must be within"):
        resolve_safe_output_path("../outside.json", "data")


def test_resolve_safe_output_path_allows_project_relative_data_path():
    path = resolve_safe_output_path("data/reports/example.json", "data")

    assert path == (Path.cwd() / "data" / "reports" / "example.json").resolve()


def test_comprehensive_report_rejects_paths_outside_data():
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

    with pytest.raises(ValueError, match="Output path must be within"):
        app.save_discovery_report({"ok": True}, "../outside.json")


def test_social_discovery_report_rejects_paths_outside_data():
    engine = SocialMusicDiscoveryEngine({})

    with pytest.raises(ValueError, match="Output path must be within"):
        engine.save_discovery_report({"ok": True}, "../outside.json")
