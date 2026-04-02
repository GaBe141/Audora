"""Security-focused tests for report path handling in main_app."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp


def test_save_discovery_report_rejects_path_traversal(tmp_path: Path) -> None:
    app = ComprehensiveMusicDiscoveryApp(config_file=str(tmp_path / "missing_config.json"))

    with pytest.raises(ValueError, match="within data/"):
        app.save_discovery_report({"ok": True}, custom_filename="../../etc/passwd")


def test_save_discovery_report_stays_inside_data_dir(tmp_path: Path) -> None:
    app = ComprehensiveMusicDiscoveryApp(config_file=str(tmp_path / "missing_config.json"))
    path = Path(app.save_discovery_report({"ok": True}, custom_filename="nested/report.json"))

    assert path.exists()
    assert path.is_file()
    assert path.resolve().is_relative_to(app.reports_dir.resolve())
