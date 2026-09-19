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

SIGNING_KEY = b"test-cache-signing-key"


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

    def test_json_round_trip(self):
        payload = serialize_cache_value({"artist": "A", "score": 9.5}, SIGNING_KEY)
        assert deserialize_cache_value(payload, SIGNING_KEY) == {"artist": "A", "score": 9.5}

    def test_bytes_round_trip(self):
        payload = serialize_cache_value(b"binary-cache", SIGNING_KEY)
        assert deserialize_cache_value(payload, SIGNING_KEY) == b"binary-cache"

    def test_dataframe_round_trip(self):
        frame = pd.DataFrame({"track": ["One"], "score": [88.0]})
        payload = serialize_cache_value(frame, SIGNING_KEY)
        restored = deserialize_cache_value(payload, SIGNING_KEY)
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(restored.reset_index(drop=True), frame)

    def test_rejects_legacy_pickle_payload(self):
        assert deserialize_cache_value(pickle.dumps({"owned": True}), SIGNING_KEY) is None

    def test_rejects_tampered_signature(self):
        payload = serialize_cache_value({"ok": True}, SIGNING_KEY)
        envelope = json.loads(payload.decode("utf-8"))
        flipped = "0" if envelope["sig"][0] != "0" else "1"
        envelope["sig"] = flipped + envelope["sig"][1:]
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        assert deserialize_cache_value(tampered, SIGNING_KEY) is None

    def test_rejects_wrong_signing_key(self):
        payload = serialize_cache_value({"ok": True}, SIGNING_KEY)
        assert deserialize_cache_value(payload, b"other-key") is None

    def test_rejects_unsupported_objects(self):
        class NotSerializable:
            pass

        with pytest.raises(TypeError, match="JSON-serializable"):
            serialize_cache_value(NotSerializable(), SIGNING_KEY)

    def test_rejects_unsigned_json_blob(self):
        raw = json.dumps({"v": 2, "kind": "json", "data": {"x": 1}}).encode("utf-8")
        assert deserialize_cache_value(raw, SIGNING_KEY) is None

    def test_envelope_uses_hmac_sha256(self):
        payload = serialize_cache_value("value", SIGNING_KEY)
        envelope = json.loads(payload.decode("utf-8"))
        stored = base64.b64decode(envelope["payload"])
        expected = hmac.new(SIGNING_KEY, stored, hashlib.sha256).hexdigest()
        assert envelope["alg"] == "HMAC-SHA256"
        assert envelope["sig"] == expected
