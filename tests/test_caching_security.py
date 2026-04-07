"""Security-focused tests for cache key generation."""

from core.caching import CacheManager, LocalCacheBackend


def test_cache_key_uses_sha256_for_args_and_kwargs():
    """Ensure cache key hashing avoids weak algorithms like MD5."""
    manager = CacheManager(backend=LocalCacheBackend())

    key = manager._build_cache_key("prefix", args=("hello", 1), kwargs={"x": "y"})
    parts = key.split(":")

    # prefix + hash(args) + hash(kwargs)
    assert len(parts) == 3
    assert parts[0] == "prefix"
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64
