"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time
from io import StringIO
from unittest.mock import MagicMock

import pandas as pd
import pytest

from core.caching import (
    _REJECTED,
    CACHE_ENVELOPE_VERSION,
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

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"z": 3})
        digest = key.split(":")[-1]
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


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


def _detached_redis_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._client = MagicMock()
    backend.key_prefix = "audora"
    return backend


class TestRedisJsonSerialization:
    """Redis payloads must be HMAC-signed JSON, never pickle."""

    def test_json_roundtrip(self):
        backend = _detached_redis_backend()
        payload = backend._serialize({"track": "song", "score": 91})
        assert json.loads(payload.decode("utf-8"))["v"] == CACHE_ENVELOPE_VERSION
        assert backend._deserialize(payload) == {"track": "song", "score": 91}

    def test_bytes_roundtrip(self):
        backend = _detached_redis_backend()
        payload = backend._serialize(b"binary-cache")
        assert backend._deserialize(payload) == b"binary-cache"

    def test_dataframe_roundtrip_uses_buffer_not_path(self):
        backend = _detached_redis_backend()
        frame = pd.DataFrame({"track": ["a", "b"], "score": [1, 2]})
        payload = backend._serialize(frame)
        restored = backend._deserialize(payload)
        pd.testing.assert_frame_equal(restored.reset_index(drop=True), frame)

        inner = json.loads(payload.decode("utf-8"))
        decoded_inner = json.loads(base64.b64decode(inner["payload"]))
        # Parsing through StringIO keeps pandas from treating JSON as a filesystem path.
        again = pd.read_json(StringIO(decoded_inner["data"]), orient="split")
        pd.testing.assert_frame_equal(again.reset_index(drop=True), frame)

    def test_rejects_legacy_pickle_bytes(self):
        backend = _detached_redis_backend()
        assert backend._deserialize(b"\x80\x04}q\x00.") is _REJECTED

    def test_rejects_signed_v1_pickle_envelope(self):
        backend = _detached_redis_backend()
        pickled = pickle.dumps({"owned": True})
        signature = hmac.new(backend._signing_key, pickled, hashlib.sha256).hexdigest()
        legacy = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert backend._deserialize(legacy) is _REJECTED

    def test_rejects_tampered_signature(self):
        backend = _detached_redis_backend()
        envelope = json.loads(backend._serialize({"ok": True}).decode("utf-8"))
        envelope["sig"] = "0" * 64
        assert backend._deserialize(json.dumps(envelope).encode("utf-8")) is _REJECTED

    def test_unsupported_object_is_not_serialized(self):
        backend = _detached_redis_backend()
        with pytest.raises(TypeError, match="Unsupported cache value type"):
            backend._serialize(object())

    def test_get_deletes_rejected_payloads(self):
        backend = _detached_redis_backend()
        backend._client.get.return_value = b"not-a-valid-envelope"
        assert backend.get("audora:bad") is None
        backend._client.delete.assert_called_once_with("audora:bad")

    def test_clear_scans_prefix_and_never_flushdb(self):
        backend = _detached_redis_backend()
        backend._client.scan.return_value = (0, [b"audora:a", b"audora:b"])
        backend.clear()
        backend._client.scan.assert_called()
        backend._client.flushdb.assert_not_called()
        backend._client.delete.assert_called_once_with(b"audora:a", b"audora:b")

    def test_clear_without_prefix_is_refused(self):
        backend = _detached_redis_backend()
        backend.key_prefix = ""
        backend.clear()
        backend._client.scan.assert_not_called()
        backend._client.flushdb.assert_not_called()
