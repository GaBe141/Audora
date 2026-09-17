"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time

import pandas as pd

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


class _FakeRedisClient:
    """Minimal Redis-like store for serialization tests."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.store[key] = value

    def setex(self, key: str, ttl: int, value: bytes) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)

    def exists(self, key: str) -> int:
        return 1 if key in self.store else 0

    def flushdb(self) -> None:
        self.store.clear()


def _signed_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._client = _FakeRedisClient()
    return backend


class TestRedisJsonSerialization:
    """Redis backend must never unpickle attacker-controlled cache entries."""

    def test_roundtrip_json_value(self):
        backend = _signed_backend()
        backend.set("json-key", {"track": "Song", "score": 91})
        assert backend.get("json-key") == {"track": "Song", "score": 91}

    def test_roundtrip_bytes_value(self):
        backend = _signed_backend()
        backend.set("bytes-key", b"binary-cache")
        assert backend.get("bytes-key") == b"binary-cache"

    def test_roundtrip_dataframe(self):
        backend = _signed_backend()
        frame = pd.DataFrame({"track": ["A"], "score": [88.5]})
        backend.set("df-key", frame)
        restored = backend.get("df-key")
        pd.testing.assert_frame_equal(restored, frame)

    def test_rejects_signed_pickle_payload(self):
        backend = _signed_backend()
        pickled = pickle.dumps({"pwned": True})
        signature = hmac.new(backend._signing_key, pickled, hashlib.sha256).hexdigest()
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": signature,
            "payload": base64.b64encode(pickled).decode("ascii"),
        }
        backend._client.set("evil", json.dumps(envelope).encode("utf-8"))
        assert backend.get("evil") is None
        assert backend.exists("evil") is False

    def test_rejects_tampered_signature(self):
        backend = _signed_backend()
        backend.set("safe", {"ok": True})
        raw = backend._client.get("safe")
        assert raw is not None
        envelope = json.loads(raw.decode("utf-8"))
        envelope["sig"] = "0" * 64
        backend._client.set("safe", json.dumps(envelope).encode("utf-8"))
        assert backend.get("safe") is None

    def test_rejects_unsupported_objects(self):
        backend = _signed_backend()
        backend.set("bad", object())
        assert backend.get("bad") is None

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"a": "b"})
        digest_parts = key.split(":")[1:]
        assert digest_parts
        assert all(len(part) == 64 for part in digest_parts)
