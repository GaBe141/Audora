"""Security-focused tests for Redis cache serialization and keying."""

from core.caching import CacheManager, LocalCacheBackend, RedisCacheBackend


class TestRedisCacheSerializationSecurity:
    """Validate safe serialization behavior in Redis cache backend."""

    def test_serialize_rejects_non_json_serializable_values(self):
        backend = object.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        assert backend._serialize({"ok": True}) is not None
        assert backend._serialize({1, 2, 3}) is None


class TestCacheManagerKeySecurity:
    """Validate strong cache key hashing behavior."""

    def test_build_cache_key_uses_strong_hashes(self):
        cache = CacheManager(backend=LocalCacheBackend(max_size=10))
        key = cache._build_cache_key("prefix", ("arg", 1), {"k": "v"})
        assert "md5" not in key.lower()
        parts = key.split(":")
        assert len(parts) == 3
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64
