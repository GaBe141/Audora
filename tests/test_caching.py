"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time
from datetime import datetime
from unittest.mock import MagicMock

import pandas as pd
import pytest

from core.caching import (
    LocalCacheBackend,
    RedisCacheBackend,
    _InvalidCachePayload,
)


def _redis_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._client = MagicMock()
    backend._namespace = "audora"
    return backend


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

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"a": "b"})
        digest_parts = [part for part in key.split(":") if len(part) == 64]
        assert digest_parts


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


class TestRedisJsonSerialization:
    """Redis backend must never pickle.loads attacker-controlled payloads."""

    def test_roundtrip_json_values(self):
        backend = _redis_backend()
        payload = backend._serialize({"track": "Song", "score": 91})
        assert b"pickle" not in payload.lower()
        assert backend._deserialize(payload) == {"track": "Song", "score": 91}

    def test_roundtrip_bytes_tuple_none_and_dataframe(self):
        backend = _redis_backend()
        assert backend._deserialize(backend._serialize(b"raw-bytes")) == b"raw-bytes"
        assert backend._deserialize(backend._serialize(("a", 1))) == ("a", 1)
        assert backend._deserialize(backend._serialize(None)) is None

        frame = pd.DataFrame({"track": ["One"], "score": [88.5]})
        restored = backend._deserialize(backend._serialize(frame))
        pd.testing.assert_frame_equal(restored, frame, check_dtype=False)

    def test_roundtrip_datetime(self):
        backend = _redis_backend()
        value = datetime(2026, 9, 18, 4, 0, 0)
        assert backend._deserialize(backend._serialize(value)) == value

    def test_rejects_legacy_pickle_payload(self):
        backend = _redis_backend()
        pickled = pickle.dumps({"owned": True})
        with pytest.raises(_InvalidCachePayload):
            backend._deserialize(pickled)

        signed_pickle = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": hmac.new(backend._signing_key, pickled, hashlib.sha256).hexdigest(),
            "payload": base64.b64encode(pickled).decode("ascii"),
        }
        with pytest.raises(_InvalidCachePayload):
            backend._deserialize(json.dumps(signed_pickle).encode("utf-8"))

    def test_rejects_tampered_signature(self):
        backend = _redis_backend()
        envelope = json.loads(backend._serialize("ok").decode("utf-8"))
        envelope["sig"] = "ab" * 32
        with pytest.raises(_InvalidCachePayload):
            backend._deserialize(json.dumps(envelope).encode("utf-8"))

    def test_get_deletes_invalid_payload(self):
        backend = _redis_backend()
        backend._client.get.return_value = pickle.dumps("evil")
        assert backend.get("audora:poison") is None
        backend._client.delete.assert_called_once_with("audora:poison")

    def test_unsupported_object_is_not_pickled(self):
        backend = _redis_backend()

        class NotSerializable:
            pass

        with pytest.raises(TypeError):
            backend._serialize(NotSerializable())

    def test_clear_uses_namespace_scan_not_flushdb(self):
        backend = _redis_backend()
        backend._client.scan_iter.return_value = [b"audora:a", b"audora:b"]
        backend.clear()
        backend._client.scan_iter.assert_called_once()
        backend._client.delete.assert_called_once_with(b"audora:a", b"audora:b")
        backend._client.flushdb.assert_not_called()
