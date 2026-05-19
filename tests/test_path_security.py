"""Security regression tests for file output path containment."""

from pathlib import Path

from core.main_app import AudoraDiscoveryApp
from core.utils import save_report
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_save_report_sanitizes_custom_filename(tmp_path):
    output_dir = tmp_path / "reports"

    saved_path = save_report(
        {"status": "ok"},
        filename="../../outside.json",
        output_dir=str(output_dir),
        add_timestamp=False,
    )

    assert saved_path == (output_dir.resolve() / "outside.json")
    assert saved_path.exists()


def test_main_app_report_stays_under_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = AudoraDiscoveryApp.__new__(AudoraDiscoveryApp)

    saved_path = Path(app.save_discovery_report({"status": "ok"}, "../outside.json")).resolve()

    assert saved_path == (tmp_path / "data" / "outside.json").resolve()
    assert saved_path.exists()


def test_social_discovery_report_stays_under_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine.__new__(SocialMusicDiscoveryEngine)

    saved_path = Path(engine.save_discovery_report({"status": "ok"}, "../outside.json")).resolve()

    assert saved_path == (tmp_path / "data" / "outside.json").resolve()
    assert saved_path.exists()
