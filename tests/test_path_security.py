"""Security regression tests for file output path containment."""

import sys
from pathlib import Path

INTEGRATIONS_DIR = Path(__file__).resolve().parent.parent / "integrations"
if str(INTEGRATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(INTEGRATIONS_DIR))

from core.main_app import ComprehensiveMusicDiscoveryApp  # noqa: E402
from core.utils import save_report  # noqa: E402
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine  # noqa: E402


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
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)

    saved_path = Path(app.save_discovery_report({"status": "ok"}, "../outside.json")).resolve()

    assert saved_path == (tmp_path / "data" / "outside.json").resolve()
    assert saved_path.exists()


def test_social_discovery_report_stays_under_data_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = SocialMusicDiscoveryEngine.__new__(SocialMusicDiscoveryEngine)

    saved_path = Path(engine.save_discovery_report({"status": "ok"}, "../outside.json")).resolve()

    assert saved_path == (tmp_path / "data" / "outside.json").resolve()
    assert saved_path.exists()
