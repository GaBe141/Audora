"""Security tests for report output path handling."""

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import save_report
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_save_report_sanitizes_filename_under_output_dir(tmp_path):
    output_dir = tmp_path / "reports"
    path = save_report({"ok": True}, filename="../../escape.json", output_dir=str(output_dir))

    assert path.parent == output_dir.resolve()
    assert path.name == "escape.json"


def test_social_discovery_report_sanitizes_custom_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine(config={})

    path = engine.save_discovery_report({"ok": True}, filepath="../../escape.json")

    assert path.endswith("data/escape.json")
    assert (tmp_path / "data" / "escape.json").exists()


def test_comprehensive_app_report_sanitizes_custom_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = object.__new__(ComprehensiveMusicDiscoveryApp)

    path = app.save_discovery_report({"ok": True}, custom_filename="../../escape.json")

    assert path.endswith("data/escape.json")
    assert (tmp_path / "data" / "escape.json").exists()
