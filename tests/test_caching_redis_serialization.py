"""Security tests for Redis cache serialization hardening."""

import json
from unittest.mock import MagicMock

import pytest

from core.caching import RedisCacheBackend


def _build_backend_for_tests() -> RedisCacheBackend:
    """Create a RedisCacheBackend instance without opening network connections."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    backend._client = MagicMock()
    return backend


def test_redis_cache_json_roundtrip():
    backend = _build_backend_for_tests()
    value = {"artist": "Test Artist", "score": 98, "nested": {"platform": "tiktok"}}
    serialized = backend._serialize(value)
    assert backend._deserialize(serialized) == value


def test_redis_cache_rejects_legacy_pickle_payload():
    backend = _build_backend_for_tests()
    # Legacy non-JSON payloads must be rejected (no unsafe pickle fallback).
    assert backend._deserialize(b"\x80\x05legacy-pickle-bytes") is None


def test_redis_cache_rejects_tampered_payload_signature():
    backend = _build_backend_for_tests()
    original = {"track": "Example", "score": 42}
    serialized = backend._serialize(original)
    envelope = json.loads(serialized.decode("utf-8"))
    envelope["payload"] = envelope["payload"][:-2] + "AA"
    tampered = json.dumps(envelope).encode("utf-8")
    assert backend._deserialize(tampered) is None


def test_redis_cache_rejects_unsupported_object_types():
    backend = _build_backend_for_tests()
    with pytest.raises(TypeError, match="Unsupported cache value type"):
        backend._serialize(set([1, 2, 3]))
