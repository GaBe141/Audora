"""Security tests for safe report file handling in main_app."""

import importlib
import sys
from datetime import datetime
from pathlib import Path

import pytest


class DummyAPIManager:
    """Minimal API manager stub for app construction in tests."""

    def get_config(self, _platform: str):
        return None

    def get_status_report(self):
        return {"summary": {"enabled_platforms": 0, "total_platforms": 0}, "platforms": {}}


def _build_app():
    """Create app instance without triggering full integrations setup."""
    if "social_discovery_engine" not in sys.modules:
        sys.modules["social_discovery_engine"] = importlib.import_module(
            "integrations.social_discovery_engine"
        )
    from core.main_app import ComprehensiveMusicDiscoveryApp

    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    app.api_manager = DummyAPIManager()
    app.main_engine = None
    app.extended_engine = None
    app.trending_schema = None
    app.last_discovery_run = None
    app.discovery_cache = {}
    app.analytics_data = []
    return app


def test_save_discovery_report_restricts_path_to_reports_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = _build_app()
    payload = {"timestamp": datetime.now().isoformat(), "ok": True}

    with pytest.raises(ValueError, match="within data/reports"):
        app.save_discovery_report(payload, custom_filename="../../outside.json")


def test_save_discovery_report_allows_safe_relative_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = _build_app()
    payload = {"timestamp": datetime.now().isoformat(), "ok": True}

    saved_path = app.save_discovery_report(payload, custom_filename="nested/report.json")
    expected_root = (tmp_path / "data" / "reports").resolve()
    saved = Path(saved_path).resolve()

    assert expected_root in saved.parents
    assert saved.name == "report.json"
    assert saved.exists()
