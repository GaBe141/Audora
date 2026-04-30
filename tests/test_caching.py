"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import json
import time
from unittest.mock import Mock

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

    def test_build_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("prefix", ("arg",), {"kw": "value"})

        parts = key.split(":")
        assert parts[0] == "prefix"
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64


class TestRedisCacheSerialization:
    """Security-focused tests for Redis cache serialization."""

    def _backend_without_init(self):
        return RedisCacheBackend.__new__(RedisCacheBackend)

    def test_json_serialization_roundtrip(self):
        backend = self._backend_without_init()
        value = {"track": "song", "score": 0.98, "tags": ["viral"]}

        serialized = backend._serialize(value)

        assert backend._deserialize(serialized) == value
        envelope = json.loads(serialized.decode("utf-8"))
        assert envelope["type"] == "json"

    def test_bytes_serialization_roundtrip(self):
        backend = self._backend_without_init()

        assert backend._deserialize(backend._serialize(b"audora")) == b"audora"

    def test_dataframe_serialization_roundtrip(self):
        backend = self._backend_without_init()
        frame = pd.DataFrame({"track": ["one", "two"], "score": [1, 2]})

        restored = backend._deserialize(backend._serialize(frame))

        pd.testing.assert_frame_equal(restored, frame)

    def test_rejects_pickle_payload_without_loading(self):
        backend = self._backend_without_init()

        assert backend._deserialize(b"\x80\x04}q\x00.") is None

    def test_rejects_unsupported_object_types(self):
        backend = self._backend_without_init()

        with pytest.raises(TypeError, match="JSON-serializable"):
            backend._serialize(object())

    def test_deletes_malformed_redis_payload_on_get(self):
        backend = self._backend_without_init()
        backend._client = Mock()
        backend._client.get.return_value = b"not-json"

        assert backend.get("bad-key") is None
        backend._client.delete.assert_called_once_with("bad-key")

    def test_cache_manager_set_ignores_unsupported_redis_value(self):
        backend = self._backend_without_init()
        backend._client = Mock()

        manager = CacheManager(backend=backend)
        manager.set("unsupported", object())

        backend._client.set.assert_not_called()
