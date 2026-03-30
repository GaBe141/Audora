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


class _DummyRedisClient:
    """In-memory stand-in for Redis client used in serializer tests."""

    def __init__(self):
        self._store: dict[str, bytes] = {}

    def ping(self):
        return True

    def get(self, key: str):
        return self._store.get(key)

    def set(self, key: str, value: bytes):
        self._store[key] = value
        return True

    def setex(self, key: str, _ttl: int, value: bytes):
        self._store[key] = value
        return True

    def delete(self, key: str):
        self._store.pop(key, None)
        return 1

    def exists(self, key: str):
        return 1 if key in self._store else 0

    def flushdb(self):
        self._store.clear()
        return True


class TestRedisCacheBackendSerialization:
    """Security and compatibility tests for Redis cache serialization."""

    def _build_backend(self) -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._client = _DummyRedisClient()  # noqa: SLF001
        backend._signing_key = b"test-signing-key-32-bytes-minimum!"  # noqa: SLF001
        return backend

    def test_json_round_trip_common_types(self):
        backend = self._build_backend()
        value = {
            "a": [1, "x", True, None],
            "b": {"nested": 2},
            "tuple": (1, 2),
            "set": {3, 4},
            "date": "2026-03-30",
            "bytes": b"abc",
        }
        payload = backend._serialize(value)  # noqa: SLF001
        decoded = backend._deserialize(payload)  # noqa: SLF001
        assert decoded["a"] == value["a"]
        assert decoded["b"] == value["b"]
        assert decoded["tuple"] == value["tuple"]
        assert decoded["set"] == value["set"]
        assert decoded["bytes"] == value["bytes"]

    def test_dataframe_round_trip(self):
        backend = self._build_backend()
        df = pd.DataFrame({"track": ["a", "b"], "score": [90, 80]})
        payload = backend._serialize(df)  # noqa: SLF001
        decoded = backend._deserialize(payload)  # noqa: SLF001
        assert isinstance(decoded, pd.DataFrame)
        assert decoded.equals(df)

    def test_rejects_tampered_signature(self):
        backend = self._build_backend()
        raw = backend._serialize({"safe": True})  # noqa: SLF001
        envelope = json.loads(raw.decode("utf-8"))
        envelope["sig"] = "0" * 64
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(tampered) is None  # noqa: SLF001

    def test_rejects_legacy_pickle_envelope(self):
        backend = self._build_backend()
        malicious_payload = pickle.dumps({"legacy": "pickle"})
        sig = hmac.new(
            backend._signing_key, malicious_payload, hashlib.sha256  # noqa: SLF001
        ).hexdigest()
        legacy_envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": sig,
            "payload": base64.b64encode(malicious_payload).decode("ascii"),
        }
        wire = json.dumps(legacy_envelope, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(wire) is None  # noqa: SLF001
