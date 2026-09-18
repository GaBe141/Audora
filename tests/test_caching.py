"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import json
import pickle
import time

import pandas as pd
import pytest

from core.caching import (
    CacheManager,
    InvalidCachePayloadError,
    LocalCacheBackend,
    deserialize_cache_value,
    serialize_cache_value,
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


class TestRedisSafeSerialization:
    """Redis payloads must be HMAC-signed JSON, never pickle."""

    def test_json_roundtrip(self):
        key = b"unit-test-signing-key"
        original = {"track": "Song", "score": 91.5, "tags": ["pop", "dance"]}
        encoded = serialize_cache_value(original, key)
        assert pickle.dumps(original) not in encoded
        assert deserialize_cache_value(encoded, key) == original

    def test_bytes_roundtrip(self):
        key = b"unit-test-signing-key"
        original = b"\x00binary-cache\xff"
        encoded = serialize_cache_value(original, key)
        assert deserialize_cache_value(encoded, key) == original

    def test_dataframe_roundtrip(self):
        key = b"unit-test-signing-key"
        original = pd.DataFrame({"track": ["A", "B"], "score": [1.0, 2.0]})
        restored = deserialize_cache_value(serialize_cache_value(original, key), key)
        pd.testing.assert_frame_equal(original, restored, check_dtype=False)

    def test_rejects_legacy_pickle_payloads(self):
        key = b"unit-test-signing-key"
        with pytest.raises(InvalidCachePayloadError):
            deserialize_cache_value(pickle.dumps({"owned": True}), key)

    def test_rejects_unsigned_legacy_envelope(self):
        key = b"unit-test-signing-key"
        legacy = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": "abc123",
                "payload": base64.b64encode(pickle.dumps({"x": 1})).decode("ascii"),
            }
        ).encode("utf-8")
        with pytest.raises(InvalidCachePayloadError, match="legacy"):
            deserialize_cache_value(legacy, key)

    def test_rejects_tampered_signature(self):
        key = b"unit-test-signing-key"
        envelope = json.loads(serialize_cache_value({"a": 1}, key))
        body = bytearray(base64.b64decode(envelope["body"]))
        body[0] ^= 0xFF
        envelope["body"] = base64.b64encode(bytes(body)).decode("ascii")
        with pytest.raises(InvalidCachePayloadError, match="signature"):
            deserialize_cache_value(json.dumps(envelope).encode("utf-8"), key)

    def test_rejects_unsupported_types(self):
        with pytest.raises(TypeError, match="Unsupported cache value type"):
            serialize_cache_value(object(), b"unit-test-signing-key")

    def test_cache_key_uses_sha256_not_md5(self):
        backend = LocalCacheBackend(max_size=10)
        cache = CacheManager(backend=backend, key_prefix="test")
        args = (1, 2)
        args_digest = hashlib.sha256(
            json.dumps(args, sort_keys=True, default=str).encode()
        ).hexdigest()
        cache_key = cache._build_cache_key("fn", args, {})
        hash_parts = [part for part in cache_key.split(":") if part != "fn"]
        assert args_digest in cache_key
        assert hash_parts
        assert all(len(part) == 64 for part in hash_parts)


class TestRedisPrefixScopedClear:
    """RedisCacheBackend.clear must SCAN the app prefix instead of FLUSHDB."""

    def test_clear_deletes_prefixed_keys_without_flushdb(self, monkeypatch):
        from core import caching as caching_mod

        class FakeClient:
            def __init__(self) -> None:
                self.store: dict[bytes, bytes] = {
                    b"audora:keep": b"one",
                    b"audora:also": b"two",
                    b"other:app": b"leave-me",
                }
                self.flushdb_called = False

            def ping(self) -> bool:
                return True

            def scan(self, cursor=0, match=None, count=200):
                pattern = (match or "*").replace("*", "")
                keys = [key for key in self.store if key.decode().startswith(pattern)]
                return 0, keys

            def delete(self, *keys: bytes) -> int:
                for key in keys:
                    self.store.pop(key, None)
                return len(keys)

            def flushdb(self) -> None:
                self.flushdb_called = True
                self.store.clear()

        fake = FakeClient()
        monkeypatch.setattr(caching_mod, "REDIS_AVAILABLE", True)
        monkeypatch.setattr(caching_mod, "ConnectionPool", lambda **kwargs: object())
        monkeypatch.setattr(
            caching_mod,
            "redis",
            type("RedisMod", (), {"Redis": lambda connection_pool=None: fake, "ConnectionError": Exception}),
        )
        monkeypatch.setenv("AUDORA_CACHE_SIGNING_KEY", "unit-test-signing-key")

        backend = caching_mod.RedisCacheBackend(key_prefix="audora")
        backend.clear()

        assert fake.flushdb_called is False
        assert b"other:app" in fake.store
        assert b"audora:keep" not in fake.store
        assert b"audora:also" not in fake.store
