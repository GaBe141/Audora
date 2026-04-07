"""Security-focused tests for data export path handling."""

import pytest

from core.data_store import EnhancedMusicDataStore


class TestExportPathValidation:
    """Ensure CSV exports are constrained to an allowed directory."""

    def test_rejects_absolute_path_outside_export_root(self, data_store):
        with pytest.raises(ValueError, match="must be under"):
            data_store.export_to_csv("trends", "/tmp/outside.csv")

    def test_allows_relative_path_under_export_root(self, data_store):
        output_path = data_store.export_to_csv("trends", "security/test_export.csv")
        assert output_path.endswith("data/exports/security/test_export.csv")

    def test_rejects_relative_path_traversal(self, data_store):
        with pytest.raises(ValueError, match="must be under"):
            data_store.export_to_csv("trends", "../../outside.csv")

