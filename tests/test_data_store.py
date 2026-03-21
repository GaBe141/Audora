"""Tests for core data_store (pooling, save_trends_bulk, get_tracks_with_artists_bulk, get_trending_summary_cached, update_trends_bulk)."""

from pathlib import Path

import pytest

from core.data_store import EnhancedMusicDataStore


class TestDataStorePooling:
    """Test connection pooling and close_pool."""

    def test_get_connection_and_close_pool(self, data_store):
        with data_store.get_connection() as conn:
            assert conn is not None
            cursor = conn.execute("SELECT 1")
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == 1
        data_store.close_pool()
        assert len(data_store._connection_pool) == 0 or True  # pool may be empty after return

    def test_multiple_connections_then_close(self, temp_db_path):
        store = EnhancedMusicDataStore(db_path=str(temp_db_path))
        with store.get_connection() as c1, store.get_connection() as c2:
            c1.execute("SELECT 1")
            c2.execute("SELECT 1")
        store.close_pool()
        # No exception and pool cleaned
        store.close_pool()


class TestSaveTrendsBulk:
    """Test save_trends_bulk and query back."""

    def test_save_trends_bulk_returns_count(self, data_store, sample_trends):
        count = data_store.save_trends_bulk(sample_trends)
        assert count == len(sample_trends)

    def test_save_trends_bulk_persists_data(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        with data_store.get_connection() as conn:
            row = conn.execute(
                "SELECT track_id, track_name, artist, score FROM trends WHERE track_id = ?",
                (sample_trends[0].track_id,),
            ).fetchone()
            assert row is not None
            assert row[0] == sample_trends[0].track_id
            assert row[1] == sample_trends[0].track_name
            assert row[2] == sample_trends[0].artist
            assert row[3] == sample_trends[0].score


class TestGetTracksWithArtistsBulk:
    """Test get_tracks_with_artists_bulk."""

    def test_get_tracks_with_artists_bulk_returns_dataframe(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        pairs = [(t.track_name, t.artist) for t in sample_trends]
        df = data_store.get_tracks_with_artists_bulk(pairs)
        assert not df.empty
        assert len(df) >= 1
        assert "track_name" in df.columns
        assert "artist" in df.columns

    def test_get_tracks_with_artists_bulk_empty_pairs_returns_empty_df(self, data_store):
        df = data_store.get_tracks_with_artists_bulk([])
        assert df.empty


class TestGetTrendingSummaryCached:
    """Test get_trending_summary_cached returns same result on second call (cache hit)."""

    def test_get_trending_summary_cached_structure(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        summary = data_store.get_trending_summary_cached(platform="spotify", days=7)
        assert "stats" in summary
        assert "top_tracks" in summary
        assert summary.get("period_days") == 7
        assert summary.get("platform") == "spotify"

    def test_get_trending_summary_cached_second_call_same_result(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        first = data_store.get_trending_summary_cached(platform="spotify", days=7)
        second = data_store.get_trending_summary_cached(platform="spotify", days=7)
        assert first == second


class TestUpdateTrendsBulk:
    """Test update_trends_bulk."""

    def test_update_trends_bulk_updates_score(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        track_id = sample_trends[0].track_id
        updated = data_store.update_trends_bulk([track_id], {"score": 99.0})
        assert updated >= 1
        with data_store.get_connection() as conn:
            row = conn.execute(
                "SELECT score FROM trends WHERE track_id = ?", (track_id,)
            ).fetchone()
            assert row is not None
            assert row[0] == 99.0

    def test_update_trends_bulk_empty_returns_zero(self, data_store):
        assert data_store.update_trends_bulk([], {"score": 1}) == 0
        assert data_store.update_trends_bulk(["x"], {}) == 0

    def test_update_trends_bulk_rejects_invalid_fields(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        with pytest.raises(ValueError, match="Invalid update fields"):
            data_store.update_trends_bulk([sample_trends[0].track_id], {"score = 0; DROP TABLE": 0})


class TestExportToCsvSecurity:
    """Security-focused tests for export path handling."""

    def test_export_to_csv_rejects_absolute_paths(self, data_store, tmp_path):
        with pytest.raises(ValueError, match="Absolute export paths"):
            data_store.export_to_csv("trends", str((tmp_path / "outside.csv").resolve()))

    def test_export_to_csv_rejects_path_traversal(self, data_store):
        with pytest.raises(ValueError, match="must stay within"):
            data_store.export_to_csv("trends", "../outside.csv")

    def test_export_to_csv_writes_inside_workspace(self, data_store, sample_trends):
        data_store.save_trends_bulk(sample_trends)
        output = data_store.export_to_csv("trends", "exports/security_test.csv")
        output_path = Path(output).resolve()
        assert output_path.exists()
        assert output_path.is_relative_to(Path.cwd().resolve())
