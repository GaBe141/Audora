"""Security hardening regression tests."""

from core.caching import CacheManager, LocalCacheBackend


class TestCacheKeyHashing:
    """Ensure cache-key hashing uses strong digest algorithm."""

    def test_build_cache_key_uses_sha256_length_hashes(self):
        manager = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
        key = manager._build_cache_key("prefix", ("arg1", 42), {"alpha": "beta"})

        parts = key.split(":")
        assert parts[0] == "prefix"
        # args hash and kwargs hash should both be SHA-256 hex digests.
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64
