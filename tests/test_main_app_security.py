"""Security tests for safe report output paths."""

import sys
import types

import pytest

# Stub integration modules so core.main_app can be imported in isolation.
if "integrations.api_config" not in sys.modules:
    api_config_module = types.ModuleType("integrations.api_config")
    api_config_module.SocialAPIManager = object  # type: ignore[attr-defined]
    sys.modules["integrations.api_config"] = api_config_module

if "integrations.extended_platforms" not in sys.modules:
    extended_module = types.ModuleType("integrations.extended_platforms")
    extended_module.ExtendedSocialDiscoveryEngine = object  # type: ignore[attr-defined]
    sys.modules["integrations.extended_platforms"] = extended_module

if "integrations.social_discovery_engine" not in sys.modules:
    social_module = types.ModuleType("integrations.social_discovery_engine")
    social_module.SocialMusicDiscoveryEngine = object  # type: ignore[attr-defined]
    sys.modules["integrations.social_discovery_engine"] = social_module

if "integrations.trending_schema" not in sys.modules:
    schema_module = types.ModuleType("integrations.trending_schema")
    schema_module.TrendingSchema = object  # type: ignore[attr-defined]
    sys.modules["integrations.trending_schema"] = schema_module

from core.main_app import ComprehensiveMusicDiscoveryApp


class TestSaveDiscoveryReportSecurity:
    """Validate custom report filenames cannot escape data directory."""

    def test_rejects_absolute_custom_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        with pytest.raises(ValueError, match="relative path under data"):
            app.save_discovery_report({"ok": True}, custom_filename="/tmp/report.json")

    def test_rejects_path_traversal_custom_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        with pytest.raises(ValueError, match="must not escape"):
            app.save_discovery_report({"ok": True}, custom_filename="../report.json")

    def test_allows_nested_relative_path_under_data(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        output = app.save_discovery_report(
            {"ok": True},
            custom_filename="reports/safe_report.json",
        )

        assert output.endswith("data/reports/safe_report.json")
