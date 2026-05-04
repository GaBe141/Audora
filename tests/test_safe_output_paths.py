"""Tests for safe output path handling."""

import sys
from unittest.mock import MagicMock

import pytest

from core.utils import resolve_safe_output_path
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine

if "social_discovery_engine" not in sys.modules:
    _social_discovery_module = MagicMock()
    _social_discovery_module.Platform = MagicMock()
    _social_discovery_module.SocialMusicMetrics = MagicMock()
    _social_discovery_module.ViralStage = MagicMock()
    sys.modules["social_discovery_engine"] = _social_discovery_module

from core.main_app import ComprehensiveMusicDiscoveryApp


class TestSafeOutputPath:
    """Validate path traversal protections for generated files."""

    def test_rejects_absolute_paths(self):
        with pytest.raises(ValueError, match="relative"):
            resolve_safe_output_path("/tmp/report.json", "data", {".json"})

    def test_rejects_parent_directory_references(self):
        with pytest.raises(ValueError, match="parent directory"):
            resolve_safe_output_path("../report.json", "data", {".json"})

    def test_rejects_unexpected_suffix(self):
        with pytest.raises(ValueError, match="suffixes"):
            resolve_safe_output_path("report.txt", "data", {".json"})

    def test_allows_legacy_prefixed_data_paths(self):
        path = resolve_safe_output_path("data/report.json", "data", {".json"})

        assert path.name == "report.json"
        assert path.parent.name == "data"


class TestReportPathConstraints:
    """Validate report writers keep outputs in application-owned directories."""

    def test_comprehensive_report_rejects_path_traversal(self, tmp_path):
        app = ComprehensiveMusicDiscoveryApp(config_file=str(tmp_path / "social_apis.json"))

        with pytest.raises(ValueError, match="parent directory"):
            app.save_discovery_report({}, "../outside.json")

    def test_social_report_rejects_path_traversal(self):
        engine = SocialMusicDiscoveryEngine({"mock_mode": "true"})

        with pytest.raises(ValueError, match="parent directory"):
            engine.save_discovery_report({}, "../outside.json")
