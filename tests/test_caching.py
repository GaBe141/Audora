"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import time

import pandas as pd

from core.caching import (
    CACHE_ENVELOPE_VERSION,
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


class TestJsonCacheEnvelope:
    """Redis cache values must round-trip through JSON, never pickle."""

    def test_round_trip_json_values(self):
        key = b"unit-test-signing-key"
        original = {"track": "Song", "score": 91.5, "tags": ["pop", "viral"]}
        raw = serialize_cache_value(original, key)
        envelope = json.loads(raw.decode("utf-8"))
        assert envelope["v"] == CACHE_ENVELOPE_VERSION
        assert deserialize_cache_value(raw, key) == original

    def test_round_trip_bytes_and_dataframe(self):
        key = b"unit-test-signing-key"
        payload = b"\x00binary-cache-value"
        assert deserialize_cache_value(serialize_cache_value(payload, key), key) == payload

        frame = pd.DataFrame({"track": ["A"], "score": [88.0]})
        restored = deserialize_cache_value(serialize_cache_value(frame, key), key)
        assert list(restored.columns) == ["track", "score"]
        assert restored.iloc[0]["track"] == "A"

    def test_rejects_legacy_pickle_envelope_even_if_signed(self):
        key = b"unit-test-signing-key"
        pickled = b"\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00\x8c\x05pwned\x94."
        signature = hmac.new(key, pickled, hashlib.sha256).hexdigest()
        legacy = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_value(legacy, key) is None

    def test_rejects_tampered_signature(self):
        key = b"unit-test-signing-key"
        raw = bytearray(serialize_cache_value({"ok": True}, key))
        raw[-2] = (raw[-2] + 1) % 256
        assert deserialize_cache_value(bytes(raw), key) is None

    def test_sha256_cache_key_is_stable(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1, 2), {"z": 3})
        assert "md5" not in key
        assert len(key.split(":")[-1]) == 64
