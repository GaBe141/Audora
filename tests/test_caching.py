"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import time

from core.caching import (
    CacheManager,
    LocalCacheBackend,
    _deserialize_cache_value,
    _serialize_cache_value,
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


class TestSignedCacheSerialization:
    """Tests for signed Redis payload serialization helpers."""

    def test_roundtrip_with_valid_signature(self):
        key = b"this-is-a-secure-signing-key-with-32+bytes"
        value = {"track": "abc123", "score": 91.2}
        encoded = _serialize_cache_value(value, key)
        decoded = _deserialize_cache_value(encoded, key)
        assert decoded == value

    def test_tampered_payload_is_rejected(self):
        key = b"this-is-a-secure-signing-key-with-32+bytes"
        value = {"track": "abc123", "score": 91.2}
        encoded = _serialize_cache_value(value, key)
        tampered = encoded.replace(b"91.2", b"99.9")
        assert _deserialize_cache_value(tampered, key) is None

    def test_unsigned_legacy_payload_is_rejected(self):
        key = b"this-is-a-secure-signing-key-with-32+bytes"
        assert _deserialize_cache_value(b"not-a-signed-envelope", key) is None

    def test_cache_key_uses_sha256_hashes(self):
        manager = CacheManager(backend=LocalCacheBackend(max_size=10), key_prefix="test")
        key = manager._build_cache_key("myfn", (1, 2), {"a": "b"})
        parts = key.split(":")
        assert len(parts) == 3
        # SHA-256 hex digest length
        assert len(parts[1]) == 64
        assert len(parts[2]) == 64


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
