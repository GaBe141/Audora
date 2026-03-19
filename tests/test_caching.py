"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import re
import time

from core.caching import (
    CacheManager,
    LocalCacheBackend,
    RedisCacheBackend,
)


class TestLocalCacheBackend:
    """Tests for LocalCacheBackend get/set/delete/exists/clear and TTL/LRU."""

    def test_set_get(self):
        backend = LocalCacheBackend(max_size=10)
        backend.set("k1", "v1")
        assert backend.get("k1") == "v1"

    def test_get_missing_returns_none(self):
        backend = LocalCacheBackend(max_size=10)
        assert backend.get("nonexistent") is None

    def test_delete(self):
        backend = LocalCacheBackend(max_size=10)
        backend.set("k1", "v1")
        backend.delete("k1")
        assert backend.get("k1") is None

    def test_exists(self):
        backend = LocalCacheBackend(max_size=10)
        assert backend.exists("k1") is False
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        backend.delete("k1")
        assert backend.exists("k1") is False

    def test_clear(self):
        backend = LocalCacheBackend(max_size=10)
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.clear()
        assert backend.get("k1") is None
        assert backend.get("k2") is None

    def test_ttl_expiration(self):
        backend = LocalCacheBackend(max_size=10)
        backend.set("k1", "v1", ttl=1)
        assert backend.get("k1") == "v1"
        time.sleep(1.1)
        assert backend.get("k1") is None

    def test_lru_eviction(self):
        backend = LocalCacheBackend(max_size=3)
        backend.set("a", 1)
        backend.set("b", 2)
        backend.set("c", 3)
        # Add 4th key; one of a,b,c must be evicted (LRU), d must be present
        backend.set("d", 4)
        assert backend.get("d") == 4
        present = sum(1 for k in ("a", "b", "c") if backend.get(k) is not None)
        assert present == 2


class TestCacheManager:
    """Tests for CacheManager with injected LocalCacheBackend."""

    def test_set_get_with_prefix(self, mock_cache):
        mock_cache.set("foo", "bar")
        assert mock_cache.get("foo") == "bar"

    def test_exists_and_delete(self, mock_cache):
        mock_cache.set("x", 1)
        assert mock_cache.exists("x") is True
        mock_cache.delete("x")
        assert mock_cache.exists("x") is False
        assert mock_cache.get("x") is None

    def test_clear(self, mock_cache):
        mock_cache.set("a", 1)
        mock_cache.set("b", 2)
        mock_cache.clear()
        assert mock_cache.get("a") is None
        assert mock_cache.get("b") is None


class TestCachedDecorator:
    """Tests for @cached decorator - call count and same result."""

    def test_cached_returns_same_result_on_second_call(self, mock_cache):
        call_count = 0

        @mock_cache.cached(ttl=60)
        def fn(x: int, y: int) -> int:
            nonlocal call_count
            call_count += 1
            return x + y

        assert fn(1, 2) == 3
        assert fn(1, 2) == 3
        assert call_count == 1

    def test_cached_different_args_calls_function_again(self, mock_cache):
        call_count = 0

        @mock_cache.cached(ttl=60)
        def fn(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x

        assert fn(1) == 1
        assert fn(2) == 2
        assert call_count == 2

    def test_cached_with_key_prefix(self, mock_cache):
        @mock_cache.cached(key_prefix="myprefix", ttl=60)
        def fn() -> str:
            return "ok"

        assert fn() == "ok"
        assert fn() == "ok"


class _FakeRedisClient:
    """Minimal fake Redis client used for secure serialization tests."""

    def __init__(self):
        self.store: dict[str, bytes] = {}

    def get(self, key: str):
        return self.store.get(key)

    def set(self, key: str, value: bytes):
        self.store[key] = value

    def setex(self, key: str, _ttl: int, value: bytes):
        self.store[key] = value

    def delete(self, key: str):
        self.store.pop(key, None)

    def exists(self, key: str):
        return int(key in self.store)


class TestRedisCacheBackendSecurity:
    """Security-focused tests for Redis payload handling."""

    def test_redis_json_roundtrip_without_pickle(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._client = _FakeRedisClient()

        payload = {"track": "Example", "score": 88}
        backend.set("k", payload, ttl=60)
        assert backend.get("k") == payload

    def test_rejects_legacy_or_invalid_binary_payload_and_evicts(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._client = _FakeRedisClient()
        backend._client.set("unsafe", b"\x80\x04legacy_pickle_payload")

        assert backend.get("unsafe") is None
        assert backend._client.get("unsafe") is None


class TestCacheKeyHashSecurity:
    """Verify cache keys use strong deterministic hashing."""

    def test_cache_key_uses_sha256_digest_format(self):
        manager = CacheManager(backend=LocalCacheBackend())

        key = manager._build_cache_key("calc", (1, "x"), {"y": 2})
        parts = key.split(":")

        assert parts[0] == "calc"
        assert len(parts) == 3
        assert re.fullmatch(r"[0-9a-f]{64}", parts[1])
        assert re.fullmatch(r"[0-9a-f]{64}", parts[2])
