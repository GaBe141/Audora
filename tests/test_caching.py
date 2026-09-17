"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import time

from core.caching import (
    LocalCacheBackend,
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


class _FakeRedis:
    """Minimal Redis stand-in for serialization tests."""

    def __init__(self) -> None:
        self.store: dict[bytes | str, bytes] = {}

    def ping(self) -> bool:
        return True

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value

    def setex(self, key, ttl, value):
        self.store[key] = value

    def delete(self, key):
        self.store.pop(key, None)

    def exists(self, key):
        return int(key in self.store)

    def flushdb(self):
        self.store.clear()


def _make_redis_backend(signing_key: bytes = b"unit-test-signing-key"):
    from core.caching import RedisCacheBackend

    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = signing_key
    backend._client = _FakeRedis()
    return backend


class TestRedisJsonSerialization:
    """Redis backend must never pickle; signed JSON envelopes only."""

    def test_json_roundtrip(self):
        backend = _make_redis_backend()
        backend.set("k", {"track": "Song", "score": 91})
        assert backend.get("k") == {"track": "Song", "score": 91}

    def test_bytes_roundtrip(self):
        backend = _make_redis_backend()
        backend.set("k", b"binary-cache")
        assert backend.get("k") == b"binary-cache"

    def test_dataframe_roundtrip(self):
        import pandas as pd

        backend = _make_redis_backend()
        frame = pd.DataFrame({"track": ["A"], "score": [80.5]})
        backend.set("k", frame)
        loaded = backend.get("k")
        assert list(loaded.columns) == ["track", "score"]
        assert loaded.iloc[0]["track"] == "A"
        assert loaded.iloc[0]["score"] == 80.5

    def test_json_null_roundtrip(self):
        backend = _make_redis_backend()
        backend.set("k", None)
        # Distinguishes a stored JSON null from a missing key by exists()
        assert backend.exists("k")
        assert backend.get("k") is None

    def test_rejects_legacy_pickle_payload(self):
        import base64
        import hashlib
        import hmac
        import json
        import pickle

        backend = _make_redis_backend()
        pickled = pickle.dumps({"pwn": True})
        signature = hmac.new(backend._signing_key, pickled, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        backend._client.set("poison", envelope)
        assert backend.get("poison") is None
        assert "poison" not in backend._client.store

    def test_rejects_tampered_signature(self):
        import json

        backend = _make_redis_backend()
        backend.set("k", {"ok": True})
        raw = backend._client.get("k")
        envelope = json.loads(raw)
        envelope["sig"] = "0" * 64
        backend._client.set("k", json.dumps(envelope).encode("utf-8"))
        assert backend.get("k") is None
        assert "k" not in backend._client.store

    def test_rejects_unsupported_object_type(self):
        backend = _make_redis_backend()
        backend.set("k", object())
        assert backend.get("k") is None

    def test_cache_keys_use_sha256_not_md5(self, mock_cache):
        import hashlib

        key = mock_cache._build_cache_key("fn", (1, 2), {"b": 3})
        assert hashlib.md5(b"not-used").hexdigest() not in key
        assert all(len(part) == 64 for part in key.split(":")[1:])

