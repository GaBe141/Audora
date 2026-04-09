"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import json
import os
import time

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


class TestRedisCacheSerializationSecurity:
    """Security-focused tests for Redis payload serialization."""

    def _build_backend(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        return backend

    def test_rejects_legacy_v1_envelope(self):
        backend = self._build_backend()
        legacy_payload = b"legacy-pickle-bytes"
        legacy_envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": "deadbeef",
            "payload": base64.b64encode(legacy_payload).decode("ascii"),
        }
        serialized = json.dumps(legacy_envelope).encode("utf-8")
        assert backend._deserialize(serialized) is None

    def test_round_trip_json_safe_types(self):
        backend = self._build_backend()
        value = {
            "text": "ok",
            "int": 7,
            "float": 3.14,
            "bool": True,
            "none": None,
            "bytes": b"abc",
            "tuple": ("x", 1),
            "set": {1, 2},
            "list": [1, "a", {"k": "v"}],
        }

        serialized = backend._serialize(value)
        restored = backend._deserialize(serialized)

        assert isinstance(restored, dict)
        assert restored["text"] == "ok"
        assert restored["int"] == 7
        assert restored["float"] == 3.14
        assert restored["bool"] is True
        assert restored["none"] is None
        assert restored["bytes"] == b"abc"
        assert restored["tuple"] == ("x", 1)
        assert restored["set"] == {1, 2}
        assert restored["list"] == [1, "a", {"k": "v"}]

    def test_serialize_rejects_non_string_dict_keys(self):
        backend = self._build_backend()
        with pytest.raises(TypeError):
            backend._serialize({1: "not allowed"})

    def test_build_cache_key_uses_sha256_hashes(self, mock_cache):
        cache_key = mock_cache._build_cache_key("pref", ("a", 1), {"k": "v"})
        parts = cache_key.split(":")
        assert parts[0] == "pref"
        for digest in parts[1:]:
            assert len(digest) == 64
            int(digest, 16)
