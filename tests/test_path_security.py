"""Security tests for filesystem path handling."""

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp
from core.utils import save_report
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def test_save_report_blocks_path_traversal(tmp_path):
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="Invalid report filename"):
        save_report(
            {"ok": True},
            filename="../escape.json",
            output_dir=str(output_dir),
        )


def test_main_app_save_discovery_report_blocks_path_traversal():
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="Invalid report filename"):
        app.save_discovery_report({"status": "ok"}, custom_filename="../../etc/passwd")


def test_social_engine_save_discovery_report_blocks_path_traversal():
    engine = SocialMusicDiscoveryEngine(config={})
    with pytest.raises(ValueError, match="Invalid report filename"):
        engine.save_discovery_report({"status": "ok"}, filepath="../../etc/passwd")
