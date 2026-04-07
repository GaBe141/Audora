"""Security tests for file path write constraints."""

import pytest

from core.data_store import EnhancedMusicDataStore
from core.main_app import ComprehensiveMusicDiscoveryApp


class TestExportPathSecurity:
    """Validate CSV export path traversal protections."""

    def test_export_rejects_absolute_paths(self, data_store):
        with pytest.raises(ValueError, match="Absolute export paths"):
            data_store.export_to_csv("trends", "/tmp/leak.csv")

    def test_export_rejects_path_traversal(self, data_store):
        with pytest.raises(ValueError, match="within data/exports"):
            data_store.export_to_csv("trends", "../../outside.csv")


class TestReportPathSecurity:
    """Validate discovery report write path protections."""

    def test_save_report_rejects_absolute_paths(self):
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
        with pytest.raises(ValueError, match="Absolute report paths"):
            app.save_discovery_report({"ok": True}, custom_filename="/tmp/report.json")

    def test_save_report_rejects_path_traversal(self):
        app = ComprehensiveMusicDiscoveryApp.__new__(ComprehensiveMusicDiscoveryApp)
        with pytest.raises(ValueError, match="within the data directory"):
            app.save_discovery_report({"ok": True}, custom_filename="../../report.json")
