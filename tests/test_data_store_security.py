"""Security-focused tests for data store cache key generation."""

from core.data_store import EnhancedMusicDataStore


def test_tracks_with_artists_bulk_cache_key_is_order_independent(tmp_path):
    """Equivalent pair lists should map to one deterministic cache entry."""
    store = EnhancedMusicDataStore(
        db_path=str(tmp_path / "audora_cache_key_test.db"),
        backup_dir=str(tmp_path / "backups"),
    )
    try:
        pairs_a = [("Track A", "Artist 1"), ("Track B", "Artist 2")]
        pairs_b = [("Track B", "Artist 2"), ("Track A", "Artist 1")]

        # Trigger cache population
        store.get_tracks_with_artists_bulk(pairs_a)
        store.get_tracks_with_artists_bulk(pairs_b)

        cache_keys = list(store._cache._backend._cache.keys())
        tracks_bulk_keys = [key for key in cache_keys if "tracks_bulk:" in key]
        assert len(tracks_bulk_keys) == 1
    finally:
        store.close_pool()
