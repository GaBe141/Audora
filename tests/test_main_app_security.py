"""Security tests for path handling in ComprehensiveMusicDiscoveryApp."""

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp


def test_save_discovery_report_rejects_path_traversal(tmp_path, monkeypatch):
    """Reject custom filenames that escape the configured reports directory."""
    monkeypatch.setattr("core.main_app.REPORTS_BASE_DIR", tmp_path.resolve())
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="escapes the allowed data directory"):
        app.save_discovery_report({"ok": True}, custom_filename="../../outside.json")


def test_save_discovery_report_rejects_non_json_extension(tmp_path, monkeypatch):
    """Reject non-JSON report output to keep behavior constrained."""
    monkeypatch.setattr("core.main_app.REPORTS_BASE_DIR", tmp_path.resolve())
    app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
    with pytest.raises(ValueError, match="\\.json extension"):
        app.save_discovery_report({"ok": True}, custom_filename="report.txt")

