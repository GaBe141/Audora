"""Security tests for report output path handling."""

from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEGRATIONS_DIR = REPO_ROOT / "integrations"
if str(INTEGRATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(INTEGRATIONS_DIR))

from core.main_app import ComprehensiveMusicDiscoveryApp
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


def _build_app_without_init() -> ComprehensiveMusicDiscoveryApp:
    """Create app instance without running heavy __init__ logic."""
    return ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)


def test_main_app_rejects_absolute_report_path():
    app = _build_app_without_init()
    with pytest.raises(ValueError, match="simple file name"):
        app.save_discovery_report({}, custom_filename="/tmp/report.json")


def test_main_app_rejects_parent_traversal_in_report_path():
    app = _build_app_without_init()
    with pytest.raises(ValueError, match="simple file name"):
        app.save_discovery_report({}, custom_filename="../outside.json")


def test_main_app_allows_safe_relative_report_path():
    app = _build_app_without_init()
    saved_path = app.save_discovery_report(
        {"ok": True},
        custom_filename="unit_test_report",
    )
    assert Path(saved_path).as_posix().endswith("data/reports/unit_test_report.json")


def test_social_engine_rejects_absolute_report_path():
    engine = SocialMusicDiscoveryEngine(config={})
    with pytest.raises(ValueError, match="not allowed"):
        engine.save_discovery_report({}, filepath="/tmp/report.json")


def test_social_engine_rejects_parent_traversal_report_path():
    engine = SocialMusicDiscoveryEngine(config={})
    with pytest.raises(ValueError, match="cannot traverse"):
        engine.save_discovery_report({}, filepath="../outside.json")

