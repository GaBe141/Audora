"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import json
import time

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


class TestCacheKeyHashing:
    """Tests for deterministic and secure cache key hashing."""

    def test_build_cache_key_uses_sha256_digests(self):
        manager = CacheManager(backend=LocalCacheBackend(max_size=5), key_prefix="audora_test")
        key = manager._build_cache_key("prefix", args=(1, "x"), kwargs={"a": 2})
        parts = key.split(":")

        assert parts[0] == "prefix"
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64
        assert all(ch in "0123456789abcdef" for ch in parts[1])
        assert all(ch in "0123456789abcdef" for ch in parts[2])


class TestRedisSerializationSafety:
    """Tests for safe Redis serializer/deserializer behavior."""

    @staticmethod
    def _backend() -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"unit-test-signing-key"
        return backend

    def test_dataframe_roundtrip_serialization(self):
        backend = self._backend()
        value = pd.DataFrame(
            [{"track_name": "Song A", "score": 91.2}, {"track_name": "Song B", "score": 88.0}]
        )

        serialized = backend._serialize(value)
        restored = backend._deserialize(serialized)

        assert isinstance(restored, pd.DataFrame)
        assert restored.equals(value)

    def test_deserialize_rejects_tampered_signature(self):
        backend = self._backend()
        serialized = backend._serialize({"k": "v"})
        envelope = json.loads(serialized.decode("utf-8"))
        payload = base64.b64decode(envelope["payload"].encode("ascii"), validate=True)
        tampered_payload = payload.replace(b'"v"', b'"x"')
        envelope["payload"] = base64.b64encode(tampered_payload).decode("ascii")

        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        assert backend._deserialize(tampered) is None

    def test_roundtrip_preserves_dict_with_type_like_keys(self):
        backend = self._backend()
        payload = {"__type__": "bytes", "data": "not-a-marker", "nested": {"__type__": "x"}}

        serialized = backend._serialize(payload)
        restored = backend._deserialize(serialized)

        assert restored == payload

    def test_serialize_rejects_unsupported_objects(self):
        backend = self._backend()

        class Unsupported:
            pass

        with pytest.raises(TypeError):
            backend._serialize(Unsupported())
