"""Security hardening tests for recently patched high-risk paths."""

from pathlib import Path

import pytest


def test_export_to_csv_rejects_path_outside_project(data_store, sample_trends, tmp_path):
    """Ensure export target path cannot escape project root."""
    data_store.save_trends_bulk(sample_trends)
    outside = tmp_path.parent / "outside_exports" / "outside.csv"

    with pytest.raises(ValueError, match="inside approved directory"):
        data_store.export_to_csv("trends", str(outside))


def test_export_to_csv_allows_backups_and_exports(data_store, sample_trends):
    """Allow writes only to backups/ and exports/ by default."""
    data_store.save_trends_bulk(sample_trends)

    base_dir = Path(data_store.backup_dir).parent
    backup_target = Path(data_store.backup_dir) / "trends_backup.csv"
    export_target = base_dir / "exports" / "trends_export.csv"

    backup_result = data_store.export_to_csv("trends", str(backup_target))
    export_result = data_store.export_to_csv("trends", str(export_target))

    assert Path(backup_result).exists()
    assert Path(export_result).exists()
