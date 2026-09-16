"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import hashlib
import json
import pickle
import time
from unittest.mock import MagicMock

import pytest

from core.caching import (
    CACHE_HMAC_ALG,
    REDIS_AVAILABLE,
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


class _FakeRedis:
    """Minimal in-memory Redis stand-in for serialization tests."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def ping(self) -> bool:
        return True

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def set(self, key: str, value: bytes) -> bool:
        self.store[key] = value
        return True

    def setex(self, key: str, _ttl: int, value: bytes) -> bool:
        self.store[key] = value
        return True

    def delete(self, key: str) -> int:
        return int(self.store.pop(key, None) is not None)

    def flushdb(self) -> bool:
        self.store.clear()
        return True

    def exists(self, key: str) -> int:
        return int(key in self.store)


def _make_redis_backend(monkeypatch: pytest.MonkeyPatch) -> tuple[RedisCacheBackend, _FakeRedis]:
    client = _FakeRedis()
    monkeypatch.setenv("AUDORA_CACHE_SIGNING_KEY", "unit-test-signing-key")
    monkeypatch.setattr("core.caching.ConnectionPool", MagicMock())
    monkeypatch.setattr("core.caching.redis.Redis", MagicMock(return_value=client))
    return RedisCacheBackend(), client


class TestCacheKeyHashing:
    """Cache keys must use SHA-256 rather than MD5."""

    def test_build_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"b": 3})
        parts = key.split(":")
        assert parts[0] == "fn"
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64
        args_digest = hashlib.sha256(
            json.dumps((1, 2), sort_keys=True, default=str).encode()
        ).hexdigest()
        assert parts[1] == args_digest


@pytest.mark.skipif(not REDIS_AVAILABLE, reason="redis package is not installed")
class TestRedisJsonEnvelope:
    """Redis backend must never unpickle attacker-controlled cache entries."""

    def test_json_round_trip(self, monkeypatch):
        backend, _client = _make_redis_backend(monkeypatch)
        backend.set("k", {"track": "song", "score": 9.5})
        assert backend.get("k") == {"track": "song", "score": 9.5}

    def test_bytes_round_trip(self, monkeypatch):
        backend, _client = _make_redis_backend(monkeypatch)
        backend.set("k", b"\x00binary\xff")
        assert backend.get("k") == b"\x00binary\xff"

    def test_dataframe_round_trip(self, monkeypatch):
        pandas = pytest.importorskip("pandas")
        backend, _client = _make_redis_backend(monkeypatch)
        frame = pandas.DataFrame({"track": ["a", "b"], "score": [1, 2]})
        backend.set("k", frame)
        restored = backend.get("k")
        pandas.testing.assert_frame_equal(restored, frame)

    def test_rejects_pickle_payloads(self, monkeypatch):
        backend, client = _make_redis_backend(monkeypatch)
        client.store["evil"] = pickle.dumps({"rce": True})
        assert backend.get("evil") is None
        assert "evil" not in client.store

    def test_rejects_tampered_signature(self, monkeypatch):
        backend, client = _make_redis_backend(monkeypatch)
        backend.set("k", {"ok": True})
        envelope = json.loads(client.store["k"].decode("utf-8"))
        envelope["sig"] = "0" * 64
        client.store["k"] = json.dumps(envelope).encode("utf-8")
        assert backend.get("k") is None
        assert "k" not in client.store

    def test_rejects_unsupported_objects(self, monkeypatch):
        backend, client = _make_redis_backend(monkeypatch)

        class NotSerializable:
            pass

        backend.set("k", NotSerializable())
        assert "k" not in client.store

    def test_envelope_is_signed_json(self, monkeypatch):
        import base64

        backend, client = _make_redis_backend(monkeypatch)
        backend.set("k", "value")
        envelope = json.loads(client.store["k"].decode("utf-8"))
        assert envelope["alg"] == CACHE_HMAC_ALG
        inner = json.loads(base64.b64decode(envelope["payload"]).decode("utf-8"))
        assert inner["kind"] == "json"
        assert inner["data"] == "value"

