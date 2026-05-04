"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import json
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

    def test_cache_key_uses_sha256_digest(self):
        manager = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
        key = manager._build_cache_key("prefix", ("arg",), {"kw": "value"})
        parts = key.split(":")

        assert len(parts) == 3
        assert all(len(part) == 64 for part in parts[1:])


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
    """Regression tests for safe Redis cache payload handling."""

    def test_json_payload_round_trip_without_pickle(self):
        backend = object.__new__(RedisCacheBackend)
        value = {
            "name": "track",
            "scores": [1, 2, 3],
            "blob": b"audora",
            "coords": (1, 2),
            "tags": {"viral", "new"},
        }

        serialized = backend._serialize(value)
        envelope = json.loads(serialized.decode("utf-8"))

        assert envelope["v"] == 2
        assert envelope["format"] == "json"
        restored = backend._deserialize(serialized)
        assert restored["name"] == value["name"]
        assert restored["scores"] == value["scores"]
        assert restored["blob"] == value["blob"]
        assert restored["coords"] == value["coords"]
        assert restored["tags"] == value["tags"]

    def test_rejects_legacy_signed_pickle_envelope(self):
        backend = object.__new__(RedisCacheBackend)
        legacy_payload = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": "unused",
                "payload": "gASVCgAAAAAAAAB9lIwBeJRLAXMu",
            }
        ).encode("utf-8")

        assert backend._deserialize(legacy_payload) is None

    def test_unsupported_object_is_not_serialized(self):
        backend = object.__new__(RedisCacheBackend)

        try:
            backend._serialize(object())
        except TypeError as exc:
            assert "Unsupported cache value type" in str(exc)
        else:
            raise AssertionError("unsupported objects must not be serialized")
