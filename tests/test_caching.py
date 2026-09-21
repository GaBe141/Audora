"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import time

import pytest

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
    """Redis payloads must be HMAC-signed JSON, never pickle."""

    def test_roundtrip_primitives_and_containers(self):
        from core.caching import load_signed_cache_value, sign_cache_envelope

        key = b"unit-test-signing-key"
        value = {"name": "track", "tags": ["a", "b"], "tuple": ("x", 1), "blob": b"raw"}
        loaded = load_signed_cache_value(key, sign_cache_envelope(key, value))
        assert loaded["name"] == "track"
        assert loaded["tags"] == ["a", "b"]
        assert loaded["tuple"] == ("x", 1)
        assert loaded["blob"] == b"raw"

    def test_rejects_legacy_pickle_envelope(self):
        import base64
        import hashlib
        import hmac
        import json
        import pickle

        from core.caching import load_signed_cache_value

        key = b"unit-test-signing-key"
        payload = pickle.dumps({"pwn": True})
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": hmac.new(key, payload, hashlib.sha256).hexdigest(),
                "payload": base64.b64encode(payload).decode("ascii"),
            }
        ).encode("utf-8")
        assert load_signed_cache_value(key, envelope) is None

    def test_rejects_tampered_payload(self):
        import json

        from core.caching import load_signed_cache_value, sign_cache_envelope

        key = b"unit-test-signing-key"
        envelope = json.loads(sign_cache_envelope(key, {"score": 1}).decode("utf-8"))
        envelope["payload"]["d"]["score"] = 999
        assert load_signed_cache_value(key, json.dumps(envelope).encode("utf-8")) is None

    def test_rejects_unsupported_types(self):
        from core.caching import _encode_cache_value

        with pytest.raises(TypeError, match="Unsupported cache value type"):
            _encode_cache_value(object())

    def test_dataframe_roundtrip(self):
        import pandas as pd

        from core.caching import load_signed_cache_value, sign_cache_envelope

        key = b"unit-test-signing-key"
        frame = pd.DataFrame({"track": ["a"], "score": [1.5]})
        loaded = load_signed_cache_value(key, sign_cache_envelope(key, frame))
        assert list(loaded.columns) == ["track", "score"]
        assert loaded.iloc[0]["track"] == "a"
