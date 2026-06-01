"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import json
import time

import pandas as pd
import pytest

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
    """Redis payload serialization should not use executable formats."""

    def _backend(self):
        return object.__new__(RedisCacheBackend)

    def test_json_payload_round_trips(self):
        backend = self._backend()
        value = {"artist": "Mitski", "scores": [1, 2, 3], "active": True}

        payload = backend._serialize(value)
        envelope = json.loads(payload.decode("utf-8"))

        assert envelope["type"] == "json"
        assert backend._deserialize(payload) == value

    def test_bytes_payload_round_trips(self):
        backend = self._backend()
        value = b"\x00audora\xff"

        payload = backend._serialize(value)
        envelope = json.loads(payload.decode("utf-8"))

        assert envelope["type"] == "bytes"
        assert backend._deserialize(payload) == value

    def test_dataframe_payload_round_trips(self):
        backend = self._backend()
        value = pd.DataFrame([{"track": "Song", "score": 98}])

        payload = backend._serialize(value)
        envelope = json.loads(payload.decode("utf-8"))

        assert envelope["type"] == "pandas_dataframe"
        pd.testing.assert_frame_equal(backend._deserialize(payload), value)

    def test_unsupported_object_is_not_serialized(self):
        backend = self._backend()

        with pytest.raises(TypeError):
            backend._serialize(object())

    def test_invalid_payload_is_deleted_on_read(self):
        class FakeClient:
            def __init__(self):
                self.deleted = []

            def get(self, key):
                return b"not-json"

            def delete(self, key):
                self.deleted.append(key)

        backend = self._backend()
        backend._client = FakeClient()

        assert backend.get("legacy") is None
        assert backend._client.deleted == ["legacy"]


class TestCacheKeyHashing:
    """Cache keys should use strong deterministic digests."""

    def test_build_cache_key_uses_sha256_components(self):
        cache = CacheManager(backend=LocalCacheBackend(), key_prefix="audora_test")

        cache_key = cache._build_cache_key("prefix", ("artist",), {"region": "global"})
        _, args_digest, kwargs_digest = cache_key.split(":")

        assert len(args_digest) == 64
        assert len(kwargs_digest) == 64
