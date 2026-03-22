"""Security-focused tests for cache key construction."""

from core.caching import CacheManager


def test_cache_key_uses_sha256_hash_segments():
    cache = CacheManager()
    key = cache._build_cache_key("prefix", (1, "x"), {"b": 2, "a": 1})
    parts = key.split(":")

    # prefix + args hash + kwargs hash
    assert len(parts) == 3
    assert parts[0] == "prefix"
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64
    assert all(c in "0123456789abcdef" for c in parts[1])
    assert all(c in "0123456789abcdef" for c in parts[2])

