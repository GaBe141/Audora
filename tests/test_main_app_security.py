"""Security tests for safe report output paths."""

import importlib
import sys
import types

import pytest

def _load_app_class(monkeypatch):
    """Import core.main_app with isolated dependency stubs."""
    api_config_module = types.ModuleType("integrations.api_config")
    api_config_module.SocialAPIManager = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "integrations.api_config", api_config_module)

    extended_module = types.ModuleType("integrations.extended_platforms")
    extended_module.ExtendedSocialDiscoveryEngine = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "integrations.extended_platforms", extended_module)

    social_module = types.ModuleType("integrations.social_discovery_engine")
    social_module.SocialMusicDiscoveryEngine = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "integrations.social_discovery_engine", social_module)

    schema_module = types.ModuleType("integrations.trending_schema")
    schema_module.TrendingSchema = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "integrations.trending_schema", schema_module)

    monkeypatch.delitem(sys.modules, "core.main_app", raising=False)
    main_app_module = importlib.import_module("core.main_app")
    return main_app_module.ComprehensiveMusicDiscoveryApp


class TestSaveDiscoveryReportSecurity:
    """Validate custom report filenames cannot escape data directory."""

    def test_rejects_absolute_custom_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ComprehensiveMusicDiscoveryApp = _load_app_class(monkeypatch)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        with pytest.raises(ValueError, match="relative path under data"):
            app.save_discovery_report({"ok": True}, custom_filename="/tmp/report.json")

    def test_rejects_path_traversal_custom_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ComprehensiveMusicDiscoveryApp = _load_app_class(monkeypatch)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        with pytest.raises(ValueError, match="must not escape"):
            app.save_discovery_report({"ok": True}, custom_filename="../report.json")

    def test_allows_nested_relative_path_under_data(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ComprehensiveMusicDiscoveryApp = _load_app_class(monkeypatch)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

        output = app.save_discovery_report(
            {"ok": True},
            custom_filename="reports/safe_report.json",
        )

        assert output.endswith("data/reports/safe_report.json")
