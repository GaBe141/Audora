"""Security tests for report path handling in main app."""

from pathlib import Path

import pytest

from core.main_app import ComprehensiveMusicDiscoveryApp


def _make_app_without_init() -> ComprehensiveMusicDiscoveryApp:
    # Avoid initializing external API clients in constructor for these unit tests.
    return ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)


class TestDiscoveryReportPathSecurity:
    """Verify save_discovery_report prevents path traversal."""

    def test_rejects_invalid_custom_filename(self):
        app = _make_app_without_init()
        with pytest.raises(ValueError, match="valid file name"):
            app.save_discovery_report({"ok": True}, custom_filename="..")

    def test_sanitizes_nested_custom_path_to_data_dir(self):
        app = _make_app_without_init()
        output = app.save_discovery_report({"ok": True}, custom_filename="../evil.json")
        assert output.endswith("/data/evil.json")

    def test_default_report_path_is_inside_data_dir(self):
        app = _make_app_without_init()
        output = app.save_discovery_report({"ok": True})
        assert Path(output).resolve().parent.name == "data"

