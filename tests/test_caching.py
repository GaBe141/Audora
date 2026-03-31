"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import time

import pandas as pd
import pytest

from core.caching import (
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


class TestRedisSerialization:
    """Tests for secure Redis payload serialization helpers."""

    @pytest.fixture
    def redis_backend(self):
        backend = object.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        return backend

    def test_serializes_json_native_values(self, redis_backend):
        payload = redis_backend._serialize_payload({"a": 1, "b": [1, 2, 3], "ok": True})
        assert payload["t"] == "json"
        assert payload["v"]["a"] == 1

    def test_serializes_and_deserializes_dataframe(self, redis_backend):
        df = pd.DataFrame({"artist": ["A", "B"], "score": [91.2, 87.5]})
        payload = redis_backend._serialize_payload(df)
        assert payload["t"] == "pd.DataFrame"
        restored = redis_backend._deserialize_payload(payload)
        pd.testing.assert_frame_equal(restored, df)

    def test_rejects_unsupported_types(self, redis_backend):
        with pytest.raises(TypeError, match="Unsupported cache value type"):
            redis_backend._serialize_payload(set([1, 2, 3]))

    def test_rejects_legacy_pickle_envelope_version(self, redis_backend):
        legacy_payload = b"legacy-pickle-bytes"
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": "deadbeef",
            "payload": base64.b64encode(legacy_payload).decode("ascii"),
        }
        encoded = b'{"v":1,"alg":"HMAC-SHA256","sig":"deadbeef","payload":"%s"}' % envelope[
            "payload"
        ].encode("ascii")
        assert redis_backend._deserialize(encoded) is None
