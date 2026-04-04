"""Tests for deterministic and stable cache key behavior in data store bulk lookups."""

from core.data_store import EnhancedMusicDataStore


class RecordingCache:
    """Minimal cache stub that records accessed keys."""

    def __init__(self) -> None:
        self.last_get_key: str | None = None

    def get(self, key: str):
        self.last_get_key = key
        return None

    def set(self, key: str, value, ttl: int | None = None):
        return None

    def delete(self, key: str):
        return None

    def clear(self):
        return None

    def exists(self, key: str) -> bool:
        return False


class TestDataStoreCacheKeyStability:
    """Ensure cache keys do not depend on randomized Python hash()."""

    def test_bulk_query_cache_key_is_order_invariant(self, temp_db_path):
        store = EnhancedMusicDataStore(db_path=str(temp_db_path))
        recorder = RecordingCache()
        store._cache = recorder  # type: ignore[assignment]

        pairs_a = [("Song A", "Artist 1"), ("Song B", "Artist 2")]
        pairs_b = [("Song B", "Artist 2"), ("Song A", "Artist 1")]

        store.get_tracks_with_artists_bulk(pairs_a)
        key_a = recorder.last_get_key
        store.get_tracks_with_artists_bulk(pairs_b)
        key_b = recorder.last_get_key

        assert key_a is not None
        assert key_b is not None
        assert key_a == key_b
