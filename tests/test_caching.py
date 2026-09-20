"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import json
import time
from pathlib import Path

import pandas as pd

from core.caching import (
    CACHE_ENVELOPE_VERSION,
    LocalCacheBackend,
    deserialize_cache_value,
    serialize_cache_value,
)

SIGNING_KEY = b"unit-test-cache-signing-key"


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
    """Signed JSON envelope must round-trip safe types and reject pickle/legacy payloads."""

    def test_roundtrip_json_compatible_value(self):
        payload = serialize_cache_value({"tracks": 3, "ok": True}, SIGNING_KEY)
        assert deserialize_cache_value(payload, SIGNING_KEY) == {"tracks": 3, "ok": True}

    def test_roundtrip_bytes_and_dataframe(self):
        raw = deserialize_cache_value(serialize_cache_value(b"secret-bytes", SIGNING_KEY), SIGNING_KEY)
        assert raw == b"secret-bytes"

        frame = pd.DataFrame({"track": ["a", "b"], "score": [1.5, 2.0]})
        restored = deserialize_cache_value(serialize_cache_value(frame, SIGNING_KEY), SIGNING_KEY)
        assert isinstance(restored, pd.DataFrame)
        pd.testing.assert_frame_equal(
            restored.reset_index(drop=True),
            frame.reset_index(drop=True),
            check_dtype=False,
        )

    def test_rejects_tampered_signature(self):
        payload = bytearray(serialize_cache_value("ok", SIGNING_KEY))
        payload[-2] = (payload[-2] + 1) % 256
        assert deserialize_cache_value(bytes(payload), SIGNING_KEY) is None

    def test_rejects_legacy_pickle_envelope(self):
        fake_pickle = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode("ascii")
        envelope = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "sig": "00", "payload": fake_pickle}
        ).encode("utf-8")
        assert deserialize_cache_value(envelope, SIGNING_KEY) is None

    def test_rejects_unsigned_payload(self):
        inner = json.dumps({"kind": "json", "data": "stolen"}).encode("utf-8")
        envelope = json.dumps(
            {
                "v": CACHE_ENVELOPE_VERSION,
                "alg": "HMAC-SHA256",
                "sig": "0" * 64,
                "payload": base64.b64encode(inner).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_value(envelope, SIGNING_KEY) is None

    def test_caching_module_does_not_use_pickle(self):
        source = Path("core/caching.py").read_text(encoding="utf-8")
        assert "import pickle" not in source
        assert "pickle.loads" not in source
        assert "pickle.dumps" not in source
        assert "hashlib.md5" not in source

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1,), {"q": "x"})
        expected_args = hashlib.sha256(
            json.dumps((1,), sort_keys=True, default=str).encode()
        ).hexdigest()
        assert expected_args in key
