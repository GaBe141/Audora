"""Tests for core caching (LocalCacheBackend, CacheManager, @cached decorator)."""

import fnmatch
import json
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

    def test_cache_key_uses_sha256(self, mock_cache):
        key = mock_cache._build_cache_key("fn", (1,), {"a": 2})
        parts = key.split(":")
        assert parts[0] == "fn"
        assert all(len(part) == 64 for part in parts[1:])


class FakeRedis:
    """In-memory Redis stand-in that refuses FLUSHDB."""

    def __init__(self):
        self.store: dict[str | bytes, bytes] = {}
        self.flushdb_called = False

    def ping(self):
        return True

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value
        return True

    def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    def delete(self, *keys):
        count = 0
        for key in keys:
            if key in self.store:
                del self.store[key]
                count += 1
        return count

    def flushdb(self):
        self.flushdb_called = True
        raise AssertionError("FLUSHDB must not be used")

    def exists(self, key):
        return 1 if key in self.store else 0

    def scan(self, cursor=0, match=None, count=None):
        keys = list(self.store.keys())
        if match:
            pattern = match.decode() if isinstance(match, bytes) else match

            def _matches(stored_key):
                text = stored_key.decode() if isinstance(stored_key, bytes) else stored_key
                return fnmatch.fnmatch(text, pattern)

            keys = [key for key in keys if _matches(key)]
        return 0, keys


def _make_redis_backend() -> tuple[RedisCacheBackend, FakeRedis]:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._key_prefix = "audora"
    fake = FakeRedis()
    backend._client = fake
    return backend, fake


class TestRedisJsonSerialization:
    """Redis backend must never pickle and must reject legacy payloads."""

    def test_json_round_trip(self):
        backend, _fake = _make_redis_backend()
        backend.set("audora:json", {"track": "Song", "score": 9.5})
        assert backend.get("audora:json") == {"track": "Song", "score": 9.5}

    def test_bytes_round_trip(self):
        backend, _fake = _make_redis_backend()
        backend.set("audora:bytes", b"binary-payload")
        assert backend.get("audora:bytes") == b"binary-payload"

    def test_dataframe_round_trip(self):
        backend, _fake = _make_redis_backend()
        df = pd.DataFrame({"track": ["A"], "score": [1.0]})
        backend.set("audora:df", df)
        result = backend.get("audora:df")
        assert list(result.columns) == ["track", "score"]
        assert result.iloc[0]["track"] == "A"

    def test_rejects_legacy_and_pickle_payloads(self):
        backend, fake = _make_redis_backend()
        fake.store["audora:legacy"] = json.dumps({"v": 1, "payload": "AAAA"}).encode()
        fake.store["audora:pickle"] = b"\x80\x04\x95"  # pickle protocol header
        assert backend.get("audora:legacy") is None
        assert backend.get("audora:pickle") is None
        assert "audora:legacy" not in fake.store
        assert "audora:pickle" not in fake.store

    def test_rejects_tampered_signature(self):
        backend, fake = _make_redis_backend()
        backend.set("audora:tamper", {"ok": True})
        envelope = json.loads(fake.store["audora:tamper"])
        envelope["sig"] = "0" * 64
        fake.store["audora:tamper"] = json.dumps(envelope).encode()
        assert backend.get("audora:tamper") is None

    def test_rejects_unsupported_objects(self):
        backend, fake = _make_redis_backend()
        backend.set("audora:bad", object())
        assert "audora:bad" not in fake.store

    def test_clear_uses_prefix_scan_not_flushdb(self):
        backend, fake = _make_redis_backend()
        backend.set("audora:keep-scope", {"a": 1})
        fake.store["other:app"] = b"untouched"
        backend.clear()
        assert fake.flushdb_called is False
        assert "audora:keep-scope" not in fake.store
        assert fake.store["other:app"] == b"untouched"

    def test_serialize_envelope_is_json_not_pickle(self):
        backend, _fake = _make_redis_backend()
        raw = backend._serialize({"hello": "world"})
        envelope = json.loads(raw)
        assert envelope["v"] == 2
        assert "pickle" not in json.dumps(envelope).lower()

