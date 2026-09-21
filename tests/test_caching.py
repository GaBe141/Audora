"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import json
import pickle
import time
from datetime import datetime

import pandas as pd
import pytest

from core.caching import (
    LocalCacheBackend,
    decode_cache_value,
    delete_keys_by_prefix,
    deserialize_cache_envelope,
    encode_cache_value,
    serialize_cache_envelope,
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

    def test_cache_keys_use_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("prefix", (1, 2), {"z": 3})
        digest_parts = key.split(":")[1:]
        assert digest_parts
        for part in digest_parts:
            assert len(part) == 64
            int(part, 16)


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
    """JSON cache envelopes must round-trip safe types and reject pickle."""

    def test_round_trip_nested_values(self):
        signing_key = b"unit-test-signing-key"
        original = {
            "name": "track",
            "score": 12.5,
            "tags": ("a", "b"),
            "when": datetime(2026, 1, 2, 3, 4, 5),
            "blob": b"raw-bytes",
        }
        restored = deserialize_cache_envelope(
            serialize_cache_envelope(original, signing_key), signing_key
        )
        assert restored["name"] == "track"
        assert restored["score"] == 12.5
        assert restored["tags"] == ("a", "b")
        assert restored["when"] == datetime(2026, 1, 2, 3, 4, 5)
        assert restored["blob"] == b"raw-bytes"

    def test_round_trip_dataframe(self):
        signing_key = b"unit-test-signing-key"
        frame = pd.DataFrame({"track": ["a", "b"], "score": [1, 2]})
        restored = deserialize_cache_envelope(
            serialize_cache_envelope(frame, signing_key), signing_key
        )
        pd.testing.assert_frame_equal(frame, restored, check_dtype=False)

    def test_rejects_arbitrary_objects(self):
        class Gadget:
            pass

        with pytest.raises(TypeError, match="JSON-cacheable"):
            encode_cache_value(Gadget())

    def test_rejects_legacy_pickle_envelope(self):
        signing_key = b"unit-test-signing-key"
        pickled = pickle.dumps({"x": 1})
        signature = hmac.new(signing_key, pickled, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert deserialize_cache_envelope(envelope, signing_key) is None

    def test_rejects_tampered_signature(self):
        signing_key = b"unit-test-signing-key"
        raw = serialize_cache_envelope({"ok": True}, signing_key)
        envelope = json.loads(raw.decode("utf-8"))
        envelope["sig"] = "0" * 64
        assert deserialize_cache_envelope(json.dumps(envelope).encode("utf-8"), signing_key) is None

    def test_decode_rejects_unknown_type(self):
        with pytest.raises(ValueError, match="Unsupported cache value type"):
            decode_cache_value({"t": "pickle", "d": "nope"})


class TestPrefixScopedRedisClear:
    """clear() must not FLUSHDB; it should only delete prefixed keys."""

    def test_delete_keys_by_prefix_leaves_other_keys(self):
        class FakeClient:
            def __init__(self) -> None:
                self.stored = {
                    b"audora:one": b"1",
                    b"audora:two": b"2",
                    b"other:keep": b"3",
                }

            def scan(self, cursor: int = 0, match: str = "*", count: int = 200):
                matched = [
                    key
                    for key in self.stored
                    if key.decode("utf-8").startswith(match.rstrip("*"))
                ]
                return 0, matched

            def delete(self, *keys: bytes) -> int:
                removed = 0
                for key in keys:
                    if key in self.stored:
                        del self.stored[key]
                        removed += 1
                return removed

        client = FakeClient()
        deleted = delete_keys_by_prefix(client, "audora")
        assert deleted == 2
        assert b"other:keep" in client.stored
        assert b"audora:one" not in client.stored
