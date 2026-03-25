"""Tests for core caching (LocalCacheBackend, CacheManager, Redis serializer, @cached)."""

import json
import time

from core.caching import LocalCacheBackend, RedisCacheBackend


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
        key = mock_cache._build_cache_key("fn", (1, "x"), {"a": True})
        parts = key.split(":")
        assert parts[0] == "fn"
        # SHA-256 hex digest length.
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


class TestRedisCacheSerialization:
    """Security-focused serializer/deserializer tests for Redis cache backend."""

    @staticmethod
    def _backend(*, allow_pickle: bool = False) -> RedisCacheBackend:
        backend = object.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        backend._allow_pickle = allow_pickle
        return backend

    def test_signed_json_round_trip(self):
        backend = self._backend()
        value = {"n": 1, "blob": b"abc", "items": (1, 2)}
        encoded = backend._serialize(value)
        decoded = backend._deserialize(encoded)
        assert decoded["n"] == 1
        assert decoded["blob"] == b"abc"
        # Tuples are normalized to JSON arrays in secure mode.
        assert decoded["items"] == [1, 2]

    def test_rejects_tampered_signature(self):
        backend = self._backend()
        encoded = backend._serialize({"ok": True})
        envelope = json.loads(encoded.decode("utf-8"))
        envelope["sig"] = "0" * 64
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(tampered) is None

    def test_rejects_pickle_entry_when_opt_in_disabled(self):
        pickling_backend = self._backend(allow_pickle=True)
        pickle_payload = pickling_backend._serialize({"legacy": "value"})

        secure_backend = self._backend(allow_pickle=False)
        assert secure_backend._deserialize(pickle_payload) is None

    def test_allows_pickle_entry_when_opt_in_enabled(self):
        backend = self._backend(allow_pickle=True)
        payload = backend._serialize({"legacy": "value"})
        assert backend._deserialize(payload) == {"legacy": "value"}
