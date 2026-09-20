"""Security tests for CSV export path confinement and size caps."""

import pytest


class TestCsvExportPathAndSize:
    """Exports must stay inside the database directory and be row-capped."""

    def test_rejects_path_traversal(self, data_store, tmp_path):
        outside = tmp_path.parent / "stolen.csv"
        with pytest.raises(ValueError, match="inside the data directory"):
            data_store.export_to_csv("trends", str(outside))

    def test_rejects_unknown_table_names(self, data_store, tmp_path):
        with pytest.raises(ValueError, match="Invalid table name"):
            data_store.export_to_csv("trends; DROP TABLE trends", str(tmp_path / "out.csv"))

    def test_writes_csv_next_to_database(self, data_store, sample_trends, tmp_path):
        data_store.save_trends_bulk(sample_trends)
        dest = tmp_path / "trends.csv"
        result = data_store.export_to_csv("trends", str(dest))
        assert result == str(dest.resolve())
        assert dest.exists()
        assert dest.read_text(encoding="utf-8").count("\n") >= 2
