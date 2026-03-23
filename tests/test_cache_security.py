"""Security-focused tests for Redis cache serialization."""

import base64
import hashlib
import hmac
import json
import pickle

import pytest

from core.caching import RedisCacheBackend


def _make_backend(allow_pickle: bool) -> RedisCacheBackend:
    """Construct a backend instance without network calls."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    backend._allow_pickle = allow_pickle
    return backend


def test_redis_cache_uses_json_serializer_by_default():
    backend = _make_backend(allow_pickle=False)
    value = {"track": "Song", "score": 91, "tags": ["viral", "pop"]}

    serialized = backend._serialize(value)
    envelope = json.loads(serialized.decode("utf-8"))

    assert envelope["v"] == 2
    assert envelope["ser"] == "json"
    assert backend._deserialize(serialized) == value


def test_redis_cache_rejects_non_json_values_when_pickle_disabled():
    backend = _make_backend(allow_pickle=False)

    with pytest.raises(ValueError, match="Refusing to cache non-JSON-serializable value"):
        backend._serialize({"unsupported": {1, 2, 3}})


def test_redis_cache_pickle_roundtrip_requires_explicit_opt_in():
    backend = _make_backend(allow_pickle=True)
    value = {"coords": (1, 2), "flags": {1, 2}}

    serialized = backend._serialize(value)
    envelope = json.loads(serialized.decode("utf-8"))

    assert envelope["ser"] == "pickle"
    assert backend._deserialize(serialized) == value


def test_legacy_pickle_envelope_rejected_when_pickle_disabled():
    backend = _make_backend(allow_pickle=False)
    payload = pickle.dumps({"legacy": True}, protocol=pickle.HIGHEST_PROTOCOL)
    envelope = {
        "v": 1,
        "alg": "HMAC-SHA256",
        "sig": hmac.new(backend._signing_key, payload, hashlib.sha256).hexdigest(),
        "payload": base64.b64encode(payload).decode("ascii"),
    }

    serialized = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    assert backend._deserialize(serialized) is None
