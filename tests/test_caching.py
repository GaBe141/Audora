"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import time

import pandas as pd

from core.caching import (
    _PAYLOAD_VERSION,
    LocalCacheBackend,
    RedisCacheBackend,
)


class _FakeRedis:
    """Minimal Redis stand-in for serialization tests."""

    def __init__(self) -> None:
        self.store: dict[bytes | str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.store[key] = value

    def setex(self, key: str, _ttl: int, value: bytes) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)

    def exists(self, key: str) -> int:
        return 1 if key in self.store else 0

    def flushdb(self) -> None:
        self.store.clear()


def _redis_backend() -> RedisCacheBackend:
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

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"b": 3})
        digest = key.split(":")[-1]
        assert len(digest) == 64
        assert digest == hashlib.sha256(
            json.dumps({"b": 3}, sort_keys=True, default=str).encode()
        ).hexdigest()


class TestRedisJsonEnvelope:
    """Regression tests for Redis JSON envelopes (no pickle)."""

    def test_round_trip_json_and_bytes(self):
        backend = _redis_backend()
        backend.set("json", {"track": "Song", "score": 91})
        backend.set("bytes", b"\x00\x01\xff")
        assert backend.get("json") == {"track": "Song", "score": 91}
        assert backend.get("bytes") == b"\x00\x01\xff"

    def test_round_trip_dataframe_and_tuple(self):
        backend = _redis_backend()
        frame = pd.DataFrame({"artist": ["A"], "score": [12.5]})
        backend.set("df", frame)
        backend.set("tuple", ("a", 1))
        restored = backend.get("df")
        assert isinstance(restored, pd.DataFrame)
        assert restored["artist"].tolist() == ["A"]
        assert restored["score"].tolist() == [12.5]
        assert backend.get("tuple") == ("a", 1)

    def test_rejects_legacy_and_tampered_payloads(self):
        backend = _redis_backend()
        backend._client.set("legacy", b"not-json")
        assert backend.get("legacy") is None
        assert backend._client.get("legacy") is None

        backend.set("good", {"ok": True})
        envelope = json.loads(backend._client.get("good").decode("utf-8"))
        envelope["sig"] = "0" * 64
        backend._client.set("good", json.dumps(envelope).encode("utf-8"))
        assert backend.get("good") is None
        assert backend._client.get("good") is None

    def test_rejects_unsigned_pickle_shaped_payload(self):
        backend = _redis_backend()
        inner = json.dumps(
            {"v": _PAYLOAD_VERSION, "kind": "json", "payload": {"pwn": True}},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        forged = {
            "v": _PAYLOAD_VERSION,
            "alg": "HMAC-SHA256",
            "sig": hmac.new(b"wrong-key", inner, hashlib.sha256).hexdigest(),
            "body": base64.b64encode(inner).decode("ascii"),
        }
        backend._client.set("forged", json.dumps(forged).encode("utf-8"))
        assert backend.get("forged") is None

    def test_unsupported_objects_are_not_serialized(self):
        backend = _redis_backend()

        class NotSerializable:
            pass

        backend.set("obj", NotSerializable())
        assert backend.get("obj") is None

    def test_envelope_does_not_contain_pickle_protocol(self):
        backend = _redis_backend()
        backend.set("safe", {"a": 1})
        raw = backend._client.get("safe")
        assert raw is not None
        assert b"pickle" not in raw.lower()
        envelope = json.loads(raw.decode("utf-8"))
        assert "body" in envelope
        assert "payload" not in envelope
