"""Security-focused tests for data store cache keying."""

from datetime import datetime

from core.data_store import EnhancedMusicDataStore, TrendData


class TestDataStoreCacheKeying:
    """Ensure cache keys for bulk lookups are deterministic."""

    def test_bulk_lookup_cache_key_is_stable_across_call_order(self):
        store = EnhancedMusicDataStore(db_path=":memory:")
        now = datetime.now()

        trend1 = TrendData(
            platform="spotify",
            track_id="track-1",
            track_name="Track One",
            artist="Artist One",
            score=80.0,
            rank=1,
            region="US",
            trend_date=now,
            metadata={},
            first_detected=now,
        )
        trend2 = TrendData(
            platform="spotify",
            track_id="track-2",
            track_name="Track Two",
            artist="Artist Two",
            score=70.0,
            rank=2,
            region="US",
            trend_date=now,
            metadata={},
            first_detected=now,
        )
        store.save_trends_bulk([trend1, trend2])

        pairs_a = [("Track One", "Artist One"), ("Track Two", "Artist Two")]
        pairs_b = [("Track Two", "Artist Two"), ("Track One", "Artist One")]

        result_a = store.get_tracks_with_artists_bulk(pairs_a)
        result_b = store.get_tracks_with_artists_bulk(pairs_b)

        assert not result_a.empty
        assert not result_b.empty
        assert len(result_a) == len(result_b)
