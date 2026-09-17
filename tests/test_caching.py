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


class _FakeRedis:
    """Minimal Redis stand-in for serialization tests."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.deleted: list[str] = []

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.store[key] = value

    def setex(self, key: str, _ttl: int, value: bytes) -> None:
        self.store[key] = value

    def delete(self, key: str) -> int:
        self.deleted.append(key)
        existed = key in self.store
        self.store.pop(key, None)
        return int(existed)

    def exists(self, key: str) -> int:
        return int(key in self.store)

    def flushdb(self) -> None:
        self.store.clear()


def _make_redis_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._client = _FakeRedis()
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
        key = mock_cache._build_cache_key("fn", ("a",), {"b": 1})
        parts = key.split(":")
        assert parts[0] == "fn"
        assert all(len(part) == 64 for part in parts[1:])


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


class TestRedisSafeSerialization:
    """Redis payloads must be signed JSON envelopes, never pickle."""

    def test_json_roundtrip(self):
        backend = _make_redis_backend()
        backend.set("k", {"track": "Hello", "score": 91})
        assert backend.get("k") == {"track": "Hello", "score": 91}

    def test_bytes_roundtrip(self):
        backend = _make_redis_backend()
        backend.set("k", b"\x00secret-bytes\xff")
        assert backend.get("k") == b"\x00secret-bytes\xff"

    def test_dataframe_roundtrip(self):
        backend = _make_redis_backend()
        frame = pd.DataFrame({"track": ["a", "b"], "score": [1, 2]})
        backend.set("k", frame)
        loaded = backend.get("k")
        pd.testing.assert_frame_equal(loaded, frame, check_dtype=False)

    def test_rejects_pickle_payload_and_deletes_key(self):
        backend = _make_redis_backend()
        backend._client.set("k", pickle.dumps({"owned": True}))
        assert backend.get("k") is None
        assert "k" in backend._client.deleted

    def test_rejects_tampered_signature(self):
        backend = _make_redis_backend()
        backend.set("k", {"ok": True})
        envelope = json.loads(backend._client.get("k").decode("utf-8"))
        envelope["sig"] = "0" * 64
        backend._client.set("k", json.dumps(envelope).encode("utf-8"))
        assert backend.get("k") is None
        assert "k" in backend._client.deleted

    def test_rejects_legacy_unsigned_json(self):
        backend = _make_redis_backend()
        backend._client.set("k", json.dumps({"v": 1, "payload": "e30="}).encode("utf-8"))
        assert backend.get("k") is None

    def test_unsupported_object_is_not_stored(self):
        backend = _make_redis_backend()
        backend.set("k", object())
        assert backend.get("k") is None
        assert "k" not in backend._client.store

    def test_hmac_covers_payload_type(self):
        backend = _make_redis_backend()
        payload = json.dumps({"ok": True}, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(
            backend._signing_key,
            b"json\0" + payload,
            hashlib.sha256,
        ).hexdigest()
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "type": "json",
            "sig": signature,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        backend._client.set("k", json.dumps(envelope).encode("utf-8"))
        assert backend.get("k") == {"ok": True}
