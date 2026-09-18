"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import time

from core.caching import (
    LocalCacheBackend,
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


class TestSignedJsonCacheEnvelope:
    """Redis-safe serialization must not execute pickle payloads."""

    def test_json_round_trip(self):
        from core.caching import pack_cache_value, unpack_cache_value

        key = b"test-signing-key"
        packed = pack_cache_value({"track": "Song", "score": 91}, key)
        ok, value = unpack_cache_value(packed, key)
        assert ok is True
        assert value == {"track": "Song", "score": 91}

    def test_bytes_round_trip(self):
        from core.caching import pack_cache_value, unpack_cache_value

        key = b"test-signing-key"
        packed = pack_cache_value(b"binary-cache", key)
        ok, value = unpack_cache_value(packed, key)
        assert ok is True
        assert value == b"binary-cache"

    def test_dataframe_round_trip(self):
        import pandas as pd

        from core.caching import pack_cache_value, unpack_cache_value

        key = b"test-signing-key"
        original = pd.DataFrame({"track": ["A"], "score": [80.5]})
        packed = pack_cache_value(original, key)
        ok, value = unpack_cache_value(packed, key)
        assert ok is True
        assert list(value.columns) == ["track", "score"]
        assert value.iloc[0]["track"] == "A"
        assert value.iloc[0]["score"] == 80.5

    def test_rejects_legacy_pickle_envelope(self):
        import base64
        import json
        import pickle

        from core.caching import unpack_cache_value

        payload = pickle.dumps({"owned": True})
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": "00" * 32,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        ok, value = unpack_cache_value(
            json.dumps(envelope).encode("utf-8"), b"test-signing-key"
        )
        assert ok is False
        assert value is None

    def test_rejects_tampered_signature(self):
        import json

        from core.caching import pack_cache_value, unpack_cache_value

        key = b"test-signing-key"
        packed = pack_cache_value({"ok": True}, key)
        envelope = json.loads(packed.decode("utf-8"))
        envelope["p"] = json.dumps({"ok": False}, separators=(",", ":"))
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        ok, value = unpack_cache_value(tampered, key)
        assert ok is False
        assert value is None

    def test_rejects_unsupported_objects(self):
        from core.caching import pack_cache_value

        class NotSerializable:
            pass

        try:
            pack_cache_value(NotSerializable(), b"test-signing-key")
        except TypeError:
            return
        raise AssertionError("Expected TypeError for unsupported cache value")

    def test_cache_key_uses_sha256(self, mock_cache):
        import hashlib

        key = mock_cache._build_cache_key("fn", (1,), {"b": 2})
        assert hashlib.md5(b"unused").hexdigest() not in key
        assert len(key.split(":")[-1]) == 64
