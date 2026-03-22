"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

from datetime import datetime
import time

import pandas as pd

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


class TestRedisCacheSerialization:
    """Security-focused serialization tests for Redis cache payloads."""

    @staticmethod
    def _backend() -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"unit-test-signing-key"
        return backend

    def test_round_trip_safe_serialization(self):
        backend = self._backend()
        payload = {
            "name": "Audora",
            "count": 3,
            "active": True,
            "created_at": datetime(2026, 1, 2, 3, 4, 5),
            "bytes_data": b"abc123",
            "coords": (1, 2),
            "tags": {"x", "y"},
            "nested": {"items": [1, 2, {"v": "ok"}]},
        }

        raw = backend._serialize(payload)
        restored = backend._deserialize(raw)

        assert restored is not None
        assert restored["name"] == "Audora"
        assert restored["count"] == 3
        assert restored["active"] is True
        assert restored["created_at"] == datetime(2026, 1, 2, 3, 4, 5)
        assert restored["bytes_data"] == b"abc123"
        assert restored["coords"] == (1, 2)
        assert restored["tags"] == {"x", "y"}
        assert restored["nested"]["items"][2]["v"] == "ok"

    def test_round_trip_dataframe(self):
        backend = self._backend()
        frame = pd.DataFrame({"track": ["a", "b"], "score": [10, 20]})

        raw = backend._serialize(frame)
        restored = backend._deserialize(raw)

        assert isinstance(restored, pd.DataFrame)
        assert restored.equals(frame)

    def test_rejects_legacy_pickle_envelope(self):
        backend = self._backend()
        legacy_payload = b'{"v":1,"alg":"HMAC-SHA256","sig":"x","payload":"e30="}'

        assert backend._deserialize(legacy_payload) is None


class TestCacheKeyHashing:
    """Ensure cache keys use modern strong hashing."""

    def test_build_cache_key_uses_sha256_hexdigest(self):
        manager = CacheManager(backend=LocalCacheBackend(max_size=10), key_prefix="test")
        key = manager._build_cache_key("prefix", args=(1, "a"), kwargs={"b": 2})
        parts = key.split(":")

        assert parts[0] == "prefix"
        # Positional args hash + keyword args hash
        assert len(parts) == 3
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64
