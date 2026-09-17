"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import hashlib
import hmac
import json
import time
from base64 import b64encode
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_build_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("prefix", (1, 2), {"z": 3})
        assert "md5" not in key
        digest_part = key.split(":")[1]
        assert len(digest_part) == 64
        int(digest_part, 16)


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

    def ping(self) -> bool:
        return True


def _make_redis_backend(signing_key: bytes = b"test-signing-key") -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._client = _FakeRedis()
    backend._signing_key = signing_key
    return backend


class TestRedisSafeSerialization:
    """Redis cache must never unpickle attacker-controlled payloads."""

    def test_json_round_trip(self):
        backend = _make_redis_backend()
        backend.set("k", {"track": "Song", "score": 91})
        assert backend.get("k") == {"track": "Song", "score": 91}

    def test_bytes_round_trip(self):
        backend = _make_redis_backend()
        backend.set("k", b"\x00\xff binary")
        assert backend.get("k") == b"\x00\xff binary"

    def test_dataframe_round_trip(self):
        backend = _make_redis_backend()
        df = pd.DataFrame({"track": ["A"], "score": [88.5]})
        backend.set("k", df)
        got = backend.get("k")
        assert isinstance(got, pd.DataFrame)
        pd.testing.assert_frame_equal(got, df)

    def test_rejects_unsupported_objects(self):
        backend = _make_redis_backend()
        with pytest.raises(TypeError, match="Unsupported cache value type"):
            backend._serialize(object())

    def test_rejects_legacy_unsigned_payload_and_deletes_key(self):
        backend = _make_redis_backend()
        backend._client.set("poison", b'{"not": "an envelope"}')
        assert backend.get("poison") is None
        assert backend._client.get("poison") is None

    def test_rejects_tampered_signature(self):
        backend = _make_redis_backend()
        backend.set("k", {"ok": True})
        envelope = json.loads(backend._client.get("k").decode("utf-8"))
        envelope["sig"] = "0" * 64
        backend._client.set("k", json.dumps(envelope).encode("utf-8"))
        assert backend.get("k") is None
        assert backend._client.get("k") is None

    def test_rejects_pickle_shaped_payload(self):
        backend = _make_redis_backend()
        pickle_bytes = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01."
        body = json.dumps(
            {"payload": pickle_bytes.decode("latin1"), "type": "pickle", "v": 1},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(backend._signing_key, body, hashlib.sha256).hexdigest()
        envelope = {
            "alg": "HMAC-SHA256",
            "body": b64encode(body).decode("ascii"),
            "sig": signature,
            "v": 1,
        }
        backend._client.set("k", json.dumps(envelope, sort_keys=True).encode("utf-8"))
        assert backend.get("k") is None

    def test_serialize_does_not_embed_pickle_protocol(self):
        backend = _make_redis_backend()
        payload = backend._serialize({"a": 1})
        assert b"pickle" not in payload.lower()
        assert b"\\x80\\x04" not in payload

    def test_cache_manager_with_redis_backend_round_trip(self):
        backend = _make_redis_backend()
        cache = CacheManager(backend=backend, default_ttl=60, key_prefix="t")
        cache.set("json-key", [1, 2, 3])
        assert cache.get("json-key") == [1, 2, 3]


def test_signing_key_prefers_environment(monkeypatch):
    monkeypatch.setenv("AUDORA_CACHE_SIGNING_KEY", "env-secret")
    fake_redis = SimpleNamespace(
        Redis=lambda **kwargs: _FakeRedis(),
        ConnectionError=Exception,
    )
    with (
        patch("core.caching.REDIS_AVAILABLE", True),
        patch("core.caching.redis", fake_redis),
        patch("core.caching.ConnectionPool", lambda **kwargs: object()),
    ):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = RedisCacheBackend._get_signing_key(backend)
        assert backend._signing_key == b"env-secret"

