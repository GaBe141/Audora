"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import hashlib
import hmac
import json
import time

import pandas as pd
import pytest

from core.caching import (
    CACHE_ENVELOPE_VERSION,
    CacheManager,
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

    def test_cached_key_uses_sha256(self, mock_cache):
        @mock_cache.cached(ttl=60)
        def fn(x: int) -> int:
            return x

        fn(7)
        expected_digest = hashlib.sha256(
            json.dumps((7,), sort_keys=True, default=str).encode()
        ).hexdigest()
        assert mock_cache.get(f"fn:{expected_digest}") == 7


class TestSignedJsonCacheEnvelope:
    """Redis payload helpers must never deserialize pickle or unsigned data."""

    signing_key = b"unit-test-signing-key-32-bytes!!"

    def test_json_round_trip(self):
        payload = {"track": "Song", "score": 91, "tags": ["pop", "viral"]}
        raw = serialize_cache_value(payload, self.signing_key)
        assert deserialize_cache_value(raw, self.signing_key) == payload

    def test_bytes_round_trip(self):
        payload = b"\x00binary-cache-value\xff"
        raw = serialize_cache_value(payload, self.signing_key)
        assert deserialize_cache_value(raw, self.signing_key) == payload

    def test_dataframe_round_trip(self):
        frame = pd.DataFrame({"track": ["a", "b"], "score": [1.5, 2.5]})
        raw = serialize_cache_value(frame, self.signing_key)
        restored = deserialize_cache_value(raw, self.signing_key)
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(restored, frame)

    def test_rejects_unsupported_objects(self):
        class NotSerializable:
            pass

        with pytest.raises(TypeError, match="Unsupported cache value type"):
            serialize_cache_value(NotSerializable(), self.signing_key)

    def test_rejects_legacy_or_malformed_payloads(self):
        assert deserialize_cache_value(b"not-json", self.signing_key) is None
        legacy = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "00", "payload": "AAAA"}
        ).encode()
        assert deserialize_cache_value(legacy, self.signing_key) is None

    def test_rejects_tampered_signature(self):
        raw = serialize_cache_value({"ok": True}, self.signing_key)
        envelope = json.loads(raw.decode("utf-8"))
        envelope["payload"] = {"ok": False}
        envelope["sig"] = hmac.new(
            self.signing_key, b"not-the-real-payload", hashlib.sha256
        ).hexdigest()
        tampered = json.dumps(envelope).encode("utf-8")
        assert deserialize_cache_value(tampered, self.signing_key) is None

    def test_envelope_version_is_current(self):
        raw = serialize_cache_value("value", self.signing_key)
        envelope = json.loads(raw.decode("utf-8"))
        assert envelope["v"] == CACHE_ENVELOPE_VERSION
        assert "pickle" not in raw.decode("utf-8").lower()


class TestCacheManagerClear:
    """Local clear should only affect the injected backend."""

    def test_clear_uses_local_backend(self):
        backend = LocalCacheBackend(max_size=10)
        cache = CacheManager(backend=backend, key_prefix="audora_test")
        cache.set("keep-me", "value")
        cache.clear()
        assert cache.get("keep-me") is None
