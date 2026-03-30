"""Security tests for report path handling in main_app."""

from core.main_app import ComprehensiveMusicDiscoveryApp


class TestReportPathValidation:
    """Ensure discovery report paths cannot escape the reports directory."""

    def test_rejects_parent_traversal_in_custom_filename(self):
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
        try:
            app.save_discovery_report({"ok": True}, custom_filename="../escape.json")
            raise AssertionError("Expected ValueError for path traversal attempt")
        except ValueError as exc:
            assert "data/reports" in str(exc)

    def test_saves_relative_paths_under_reports_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
        output_path = app.save_discovery_report({"ok": True}, custom_filename="safe/report.json")
        assert tmp_path.joinpath("data/reports/safe/report.json").resolve() == (
            tmp_path.joinpath(output_path).resolve()
        )
