"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time

import pandas as pd
import pytest

from core.caching import (
    LocalCacheBackend,
    RedisCacheBackend,
)


def _unsigned_backend() -> RedisCacheBackend:
    """Build a Redis backend without connecting, for serialization tests."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-cache-signing-key-32bytes!!"
    backend._key_prefix = "audora"
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

    def test_build_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1,), {"b": 2})
        args_digest = hashlib.sha256(
            json.dumps((1,), sort_keys=True, default=str).encode()
        ).hexdigest()
        kwargs_digest = hashlib.sha256(
            json.dumps({"b": 2}, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert key == f"fn:{args_digest}:{kwargs_digest}"
        assert hashlib.md5(b"unused").hexdigest() not in key


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
    """Redis cache must never pickle-deserialize untrusted payloads."""

    def test_json_roundtrip(self):
        backend = _unsigned_backend()
        restored = backend._deserialize(backend._serialize({"track": "Song", "score": 91}))
        assert restored == {"track": "Song", "score": 91}

    def test_bytes_roundtrip(self):
        backend = _unsigned_backend()
        restored = backend._deserialize(backend._serialize(b"binary-cache"))
        assert restored == b"binary-cache"

    def test_dataframe_roundtrip(self):
        backend = _unsigned_backend()
        frame = pd.DataFrame({"track": ["A"], "score": [88.5]})
        restored = backend._deserialize(backend._serialize(frame))
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(restored, frame)

    def test_rejects_malformed_payload(self):
        backend = _unsigned_backend()
        assert backend._deserialize(b"not-json") is None
        assert backend._deserialize(b"{}") is None

    def test_rejects_legacy_pickle_payload(self):
        backend = _unsigned_backend()
        pickled = pickle.dumps({"rce": "payload"})
        assert backend._deserialize(pickled) is None

    def test_rejects_tampered_signature(self):
        backend = _unsigned_backend()
        raw = json.loads(backend._serialize({"ok": True}))
        raw["sig"] = "0" * 64
        assert backend._deserialize(json.dumps(raw).encode()) is None

    def test_rejects_unsigned_json_body(self):
        backend = _unsigned_backend()
        inner = json.dumps({"t": "json", "d": {"injected": True}}).encode()
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": hmac.new(b"wrong-key", inner, hashlib.sha256).hexdigest(),
            "payload": base64.b64encode(inner).decode(),
        }
        assert backend._deserialize(json.dumps(envelope).encode()) is None

    def test_unsupported_object_raises(self):
        backend = _unsigned_backend()
        with pytest.raises(TypeError, match="Unsupported Redis cache payload type"):
            backend._serialize(object())

    def test_clear_is_prefix_scoped(self):
        class FakeRedis:
            def __init__(self):
                self.store = {
                    b"audora:keep-scope": b"1",
                    b"other:leave": b"2",
                }
                self.deleted: list[bytes] = []

            def scan_iter(self, match, count=200):
                prefix = match[:-1].encode() if match.endswith("*") else match.encode()
                for key in list(self.store):
                    if key.startswith(prefix):
                        yield key

            def delete(self, key):
                self.deleted.append(key)
                self.store.pop(key, None)

            def flushdb(self):
                raise AssertionError("FLUSHDB must not be used to clear cache")

        backend = _unsigned_backend()
        backend._client = FakeRedis()
        backend.clear()
        assert b"audora:keep-scope" in backend._client.deleted
        assert b"other:leave" not in backend._client.deleted
        assert b"other:leave" in backend._client.store
