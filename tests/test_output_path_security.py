from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import resolve_safe_output_path
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_resolve_safe_output_path_rejects_parent_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="Output path"):
        resolve_safe_output_path("../outside.json")


def test_resolve_safe_output_path_keeps_relative_paths_in_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    resolved = resolve_safe_output_path("reports/result.json")

    assert resolved == tmp_path / "data" / "reports" / "result.json"


def test_main_app_report_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

    with pytest.raises(ValueError, match="Output path"):
        app.save_discovery_report({"ok": True}, "../outside.json")


def test_social_discovery_report_rejects_absolute_escape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine({"mock_mode": True})

    with pytest.raises(ValueError, match="Output path"):
        engine.save_discovery_report({"ok": True}, str(tmp_path.parent / "outside.json"))


def test_social_discovery_report_writes_inside_data(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine({"mock_mode": True})

    saved_path = Path(engine.save_discovery_report({"ok": True}, "reports/social.json"))

    assert saved_path == tmp_path / "data" / "reports" / "social.json"
    assert saved_path.exists()
