"""Security tests for report output path confinement."""

import importlib
import sys
import types

import pytest

extended_platforms = types.ModuleType("integrations.extended_platforms")
extended_platforms.ExtendedSocialDiscoveryEngine = object
sys.modules.setdefault("integrations.extended_platforms", extended_platforms)

ComprehensiveMusicDiscoveryApp = importlib.import_module(
    "core.main_app"
).ComprehensiveMusicDiscoveryApp
SocialMusicDiscoveryEngine = importlib.import_module(
    "integrations.social_discovery_engine"
).SocialMusicDiscoveryEngine


class TestReportPathSafety:
    """Validate report writers cannot escape the data directory."""

    def test_comprehensive_report_rejects_parent_traversal(self):
        app = object.__new__(ComprehensiveMusicDiscoveryApp)

        with pytest.raises(ValueError, match="data directory"):
            app._safe_report_path("../outside.json")

    def test_comprehensive_report_places_plain_filename_under_data(self):
        app = object.__new__(ComprehensiveMusicDiscoveryApp)

        path = app._safe_report_path("report.json")

        assert path.parent.name == "data"
        assert path.name == "report.json"

    def test_social_report_rejects_absolute_path_outside_data(self, tmp_path):
        engine = SocialMusicDiscoveryEngine({})

        with pytest.raises(ValueError, match="data directory"):
            engine._safe_report_path(str(tmp_path / "outside.json"))

