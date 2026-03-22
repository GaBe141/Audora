"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import time

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


class TestRedisCacheSerialization:
    """Security-focused tests for Redis cache serialization/deserialization."""

    @staticmethod
    def _make_backend() -> RedisCacheBackend:
        # Build a minimal instance without opening a Redis connection.
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        return backend

    def test_round_trip_json_value(self):
        backend = self._make_backend()
        raw = backend._serialize({"ok": True, "values": [1, 2, 3]})
        assert backend._deserialize(raw) == {"ok": True, "values": [1, 2, 3]}

    def test_rejects_tampered_signature(self):
        backend = self._make_backend()
        raw = backend._serialize({"safe": "value"})
        envelope = json.loads(raw.decode("utf-8"))
        envelope["sig"] = "0" * 64
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(tampered) is None

    def test_rejects_legacy_pickle_envelope(self):
        backend = self._make_backend()
        payload = b"legacy-pickle-bytes"
        sig = hmac.new(backend._signing_key, payload, hashlib.sha256).hexdigest()
        legacy = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": sig,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        raw = json.dumps(legacy, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(raw) is None

    def test_round_trip_dataframe_value(self):
        pd = pytest.importorskip("pandas")
        backend = self._make_backend()
        original = pd.DataFrame({"track": ["a", "b"], "score": [1, 2]})
        raw = backend._serialize(original)
        decoded = backend._deserialize(raw)
        assert decoded is not None
        assert list(decoded.columns) == ["track", "score"]
        assert decoded.to_dict("records") == original.to_dict("records")
