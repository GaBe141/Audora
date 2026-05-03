"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time
from datetime import date, datetime

import pandas as pd
import pytest

import core.caching as caching
from core.caching import (
    CACHE_ENVELOPE_VERSION,
    CACHE_PAYLOAD_ALGORITHM,
    CACHE_TYPE_MARKER,
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

    def test_cache_key_uses_sha256_digest(self, mock_cache):
        cache_key = mock_cache._build_cache_key("fn", ("value",), {"limit": 10})
        key_parts = cache_key.split(":")

        assert len(key_parts[1]) == hashlib.sha256().digest_size * 2
        assert len(key_parts[2]) == hashlib.sha256().digest_size * 2


@pytest.fixture
def redis_backend(monkeypatch):
    """Create a RedisCacheBackend instance without requiring a Redis server."""
    monkeypatch.setattr(caching, "REDIS_AVAILABLE", True)
    monkeypatch.setattr(caching, "ConnectionPool", lambda **_kwargs: object())

    class FakeRedis:
        def __init__(self, connection_pool):
            self.connection_pool = connection_pool
            self.values = {}

        def ping(self):
            return True

        def get(self, key):
            return self.values.get(key)

        def set(self, key, value):
            self.values[key] = value

        def setex(self, key, _ttl, value):
            self.values[key] = value

        def delete(self, key):
            self.values.pop(key, None)

        def flushdb(self):
            self.values.clear()

        def exists(self, key):
            return key in self.values

    class FakeRedisModule:
        ConnectionError = ConnectionError
        Redis = FakeRedis

    monkeypatch.setattr(caching, "redis", FakeRedisModule)

    backend = RedisCacheBackend()
    backend._signing_key = b"test-cache-signing-key"
    return backend


class TestRedisCacheSerialization:
    """Regression tests for safe Redis cache serialization."""

    def test_round_trips_json_supported_values(self, redis_backend):
        now = datetime(2026, 5, 3, 20, 0, 0)
        value = {
            "text": "hello",
            "bytes": b"binary",
            "tuple": ("a", 1),
            "set": {"b", "a"},
            "date": date(2026, 5, 3),
            "datetime": now,
        }

        redis_backend.set("key", value)

        assert redis_backend.get("key") == value

    def test_round_trips_dataframe(self, redis_backend):
        frame = pd.DataFrame({"track": ["a", "b"], "score": [1, 2]})

        redis_backend.set("frame", frame)

        pd.testing.assert_frame_equal(redis_backend.get("frame"), frame)

    def test_rejects_legacy_pickle_envelope_without_loading(self, redis_backend, monkeypatch):
        def fail_if_loaded(_payload):
            raise AssertionError("pickle.loads should not be called")

        legacy_payload = pickle.dumps({"unsafe": True})
        signature = hmac.new(redis_backend._signing_key, legacy_payload, hashlib.sha256).hexdigest()
        legacy_envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": base64.b64encode(legacy_payload).decode("ascii"),
        }
        monkeypatch.setattr(pickle, "loads", fail_if_loaded)

        assert redis_backend._deserialize(json.dumps(legacy_envelope).encode("utf-8")) is None

    def test_rejects_tampered_payload(self, redis_backend):
        serialized = json.loads(redis_backend._serialize({"safe": True}).decode("utf-8"))
        payload = json.loads(base64.b64decode(serialized["payload"]).decode("utf-8"))
        payload["safe"] = False
        serialized["payload"] = base64.b64encode(json.dumps(payload).encode("utf-8")).decode(
            "ascii"
        )

        assert redis_backend._deserialize(json.dumps(serialized).encode("utf-8")) is None

    def test_rejects_unsupported_object_type(self, redis_backend):
        with pytest.raises(TypeError, match="Unsupported cache value type"):
            redis_backend._serialize(object())

    def test_serialized_envelope_declares_json_format(self, redis_backend):
        envelope = json.loads(redis_backend._serialize({"safe": True}).decode("utf-8"))

        assert envelope["v"] == CACHE_ENVELOPE_VERSION
        assert envelope["alg"] == CACHE_PAYLOAD_ALGORITHM
        assert envelope["format"] == "json"

        payload = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        assert payload[CACHE_TYPE_MARKER] == "dict"
