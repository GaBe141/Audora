"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time

import pandas as pd
import pytest

from core.caching import (
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

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1,), {"b": 2})
        assert "md5" not in key
        assert len(key.split(":")[1]) == 64


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
    """Regression tests for Redis payload serialization without pickle."""

    def test_json_roundtrip(self):
        key = b"test-signing-key"
        original = {"track": "song", "score": 91.5, "tags": ["pop", "new"]}
        restored = deserialize_cache_value(serialize_cache_value(original, key), key)
        assert restored == original

    def test_bytes_roundtrip(self):
        key = b"test-signing-key"
        original = b"\x00binary\xffpayload"
        restored = deserialize_cache_value(serialize_cache_value(original, key), key)
        assert restored == original

    def test_dataframe_roundtrip(self):
        key = b"test-signing-key"
        original = pd.DataFrame({"track": ["a", "b"], "score": [1.5, 2.25]})
        restored = deserialize_cache_value(serialize_cache_value(original, key), key)
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(original, restored)

    def test_rejects_raw_pickle_payload(self):
        key = b"test-signing-key"
        payload = pickle.dumps({"owned": True})
        assert deserialize_cache_value(payload, key) is None

    def test_rejects_legacy_v1_pickle_envelope(self):
        key = b"test-signing-key"
        pickled = pickle.dumps({"owned": True})
        signature = hmac.new(key, pickled, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_value(envelope, key) is None

    def test_rejects_tampered_signature(self):
        key = b"test-signing-key"
        raw = serialize_cache_value({"ok": True}, key)
        envelope = json.loads(raw.decode("utf-8"))
        envelope["sig"] = "0" * 64
        assert deserialize_cache_value(json.dumps(envelope).encode("utf-8"), key) is None

    def test_rejects_path_like_dataframe_payload(self):
        key = b"test-signing-key"
        inner = json.dumps(
            {"v": 2, "data": {"path": "/etc/passwd"}, "type": "pandas_dataframe"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        envelope = {
            "v": 2,
            "alg": "HMAC-SHA256",
            "sig": hmac.new(key, inner, hashlib.sha256).hexdigest(),
            "payload": base64.b64encode(inner).decode("ascii"),
        }
        assert deserialize_cache_value(json.dumps(envelope).encode("utf-8"), key) is None

    def test_unsupported_object_raises(self):
        key = b"test-signing-key"
        with pytest.raises(TypeError, match="Unsupported cache payload type"):
            serialize_cache_value(object(), key)
