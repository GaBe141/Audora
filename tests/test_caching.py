"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import hashlib
import json
import time

import pandas as pd

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
    """Tests for Redis cache payload encoding and signature checks."""

    def test_encode_decode_json_value(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        raw = backend._serialize({"hello": "world", "n": 1})
        out = backend._deserialize(raw)
        assert out == {"hello": "world", "n": 1}

    def test_encode_decode_dataframe_value(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        df = pd.DataFrame(
            {
                "track": ["a", "b"],
                "score": [10, 20],
            }
        )

        raw = backend._serialize(df)
        out = backend._deserialize(raw)

        assert isinstance(out, pd.DataFrame)
        assert out.equals(df)

    def test_rejects_tampered_payload_signature(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        raw = backend._serialize({"safe": True})
        envelope = json.loads(raw.decode("utf-8"))
        envelope["payload"]["value"] = {"safe": False}
        tampered = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
        assert backend._deserialize(tampered) is None

    def test_cache_key_builder_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, "a"), {"x": 2})
        args_str = json.dumps((1, "a"), sort_keys=True, default=str)
        kwargs_str = json.dumps({"x": 2}, sort_keys=True, default=str)
        args_digest = hashlib.sha256(args_str.encode("utf-8")).hexdigest()
        kwargs_digest = hashlib.sha256(kwargs_str.encode("utf-8")).hexdigest()
        assert key == f"fn:{args_digest}:{kwargs_digest}"
