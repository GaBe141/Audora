"""Security-focused tests for cache key derivation stability and hashing."""

from core.caching import CacheManager, LocalCacheBackend


def test_cache_key_uses_sha256_hashes() -> None:
    manager = CacheManager(backend=LocalCacheBackend())
    key = manager._build_cache_key("pref", args=(1, "x"), kwargs={"a": 1})  # noqa: SLF001
    parts = key.split(":")
    # prefix + args hash + kwargs hash
    assert parts[0] == "pref"
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64


def test_cache_key_deterministic_for_same_inputs() -> None:
    manager = CacheManager(backend=LocalCacheBackend())
    key1 = manager._build_cache_key("pref", args=(1, "x"), kwargs={"a": 1})  # noqa: SLF001
    key2 = manager._build_cache_key("pref", args=(1, "x"), kwargs={"a": 1})  # noqa: SLF001
    assert key1 == key2
