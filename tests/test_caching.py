"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import base64
import hashlib
import hmac
import io
import json
import pickle
import time

import pandas as pd

from core.caching import (
    LocalCacheBackend,
    RedisCacheBackend,
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


class TestRedisCacheSerializationSecurity:
    """Security-focused tests for Redis serialization/deserialization behavior."""

    @staticmethod
    def _build_backend(*, allow_pickle: bool) -> RedisCacheBackend:
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"  # noqa: SLF001
        backend._allow_pickle = allow_pickle  # noqa: SLF001
        return backend

    @staticmethod
    def _signed_envelope(version: int, fmt: str | None, payload: bytes, key: bytes) -> bytes:
        sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
        envelope = {
            "v": version,
            "alg": "HMAC-SHA256",
            "sig": sig,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if fmt is not None:
            envelope["fmt"] = fmt
        return json.dumps(envelope).encode("utf-8")

    def test_serializes_json_compatible_values_without_pickle(self):
        backend = self._build_backend(allow_pickle=False)
        fmt, payload = backend._serialize_payload({"artist": "A", "score": 95.0})  # noqa: SLF001
        assert fmt == "json"
        assert payload == b'{"artist":"A","score":95.0}'

    def test_serializes_dataframes_without_pickle(self):
        backend = self._build_backend(allow_pickle=False)
        value = pd.DataFrame([{"track_name": "Song", "score": 88.5}])

        fmt, payload = backend._serialize_payload(value)  # noqa: SLF001

        assert fmt == "pandas_dataframe_json"
        restored = pd.read_json(io.StringIO(payload.decode("utf-8")), orient="split")
        assert restored.to_dict("records") == value.to_dict("records")

    def test_rejects_unsafe_nonserializable_values_when_pickle_disabled(self):
        backend = self._build_backend(allow_pickle=False)
        value = {1, 2, 3}  # not JSON serializable and not a dataframe

        try:
            backend._serialize_payload(value)  # noqa: SLF001
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "AUDORA_CACHE_ALLOW_PICKLE=1" in str(exc)

    def test_rejects_v1_pickled_payloads_by_default(self):
        backend = self._build_backend(allow_pickle=False)
        payload = pickle.dumps({"a": 1}, protocol=pickle.HIGHEST_PROTOCOL)
        signed = self._signed_envelope(
            version=1,
            fmt=None,
            payload=payload,
            key=backend._signing_key,  # noqa: SLF001
        )

        assert backend._deserialize(signed) is None  # noqa: SLF001

    def test_accepts_v2_pickled_payloads_only_when_enabled(self):
        backend = self._build_backend(allow_pickle=True)
        expected = {"track": "Song", "score": 91}
        payload = pickle.dumps(expected, protocol=pickle.HIGHEST_PROTOCOL)
        signed = self._signed_envelope(
            version=2,
            fmt="pickle",
            payload=payload,
            key=backend._signing_key,  # noqa: SLF001
        )

        assert backend._deserialize(signed) == expected  # noqa: SLF001
