"""Security tests for data export path handling."""

import pytest

from core.data_store import EnhancedMusicDataStore


class TestDataStoreExportSecurity:
    """Validate CSV export restrictions."""

    def test_rejects_export_path_outside_exports_directory(self, tmp_path):
        store = EnhancedMusicDataStore(str(tmp_path / "music.db"), backup_dir=str(tmp_path / "backups"))

        with pytest.raises(ValueError, match="exports directory"):
            store.export_to_csv("trends", str(tmp_path / "outside.csv"))

    def test_rejects_non_csv_export_extension(self, tmp_path):
        store = EnhancedMusicDataStore(str(tmp_path / "music.db"), backup_dir=str(tmp_path / "backups"))

        with pytest.raises(ValueError, match=".csv"):
            store.export_to_csv("trends", "unsafe.json")

    def test_rejects_unknown_export_table(self, tmp_path):
        store = EnhancedMusicDataStore(str(tmp_path / "music.db"), backup_dir=str(tmp_path / "backups"))

        with pytest.raises(ValueError, match="Invalid table"):
            store.export_to_csv("sqlite_master", "safe.csv")
