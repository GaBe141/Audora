"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import hashlib
import hmac
import json
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
    """Redis-safe serialization must never execute pickle payloads."""

    def test_round_trip_json_values(self):
        key = b"test-signing-key"
        payload = {"track": "Song", "score": 91, "tags": ["pop", "viral"]}
        raw = serialize_cache_value(payload, key)
        assert deserialize_cache_value(raw, key) == payload

    def test_round_trip_bytes(self):
        key = b"test-signing-key"
        payload = b"\x00binary-cache\xff"
        assert deserialize_cache_value(serialize_cache_value(payload, key), key) == payload

    def test_round_trip_dataframe(self):
        key = b"test-signing-key"
        frame = pd.DataFrame({"track_name": ["A"], "score": [88.5]})
        restored = deserialize_cache_value(serialize_cache_value(frame, key), key)
        assert isinstance(restored, pd.DataFrame)
        assert list(restored["track_name"]) == ["A"]
        assert restored["score"].iloc[0] == pytest.approx(88.5)

    def test_rejects_unsupported_objects(self):
        class Custom:
            pass

        with pytest.raises(TypeError, match="cannot be cached safely"):
            serialize_cache_value(Custom(), b"key")

    def test_rejects_legacy_and_unsigned_payloads(self):
        key = b"test-signing-key"
        assert deserialize_cache_value(b"not-json", key) is None
        legacy = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "x", "payload": "YQ=="}
        ).encode()
        assert deserialize_cache_value(legacy, key) is None

    def test_rejects_tampered_signature(self):
        key = b"test-signing-key"
        raw = serialize_cache_value({"ok": True}, key)
        envelope = json.loads(raw.decode())
        envelope["sig"] = "0" * 64
        assert deserialize_cache_value(json.dumps(envelope).encode(), key) is None

    def test_rejects_forged_payload_with_wrong_key(self):
        raw = serialize_cache_value({"ok": True}, b"correct-key")
        assert deserialize_cache_value(raw, b"other-key") is None

    def test_rejects_pickle_bytes_masquerading_as_envelope(self):
        # Classic pickle protocol header must not be treated as a valid cache entry.
        assert deserialize_cache_value(b"\x80\x04malicious", b"key") is None

    def test_signed_body_cannot_be_swapped_without_new_mac(self):
        key = b"test-signing-key"
        raw = serialize_cache_value({"ok": True}, key)
        envelope = json.loads(raw.decode())
        forged_inner = json.dumps(
            {"v": 2, "kind": "json", "payload": json.dumps({"pwned": True})}
        ).encode()
        envelope["body"] = __import__("base64").b64encode(forged_inner).decode("ascii")
        envelope["sig"] = hmac.new(b"attacker", forged_inner, hashlib.sha256).hexdigest()
        assert deserialize_cache_value(json.dumps(envelope).encode(), key) is None
