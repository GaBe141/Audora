"""Security-focused tests for cache serialization hardening."""

import base64
import hashlib
import hmac
import json

from core.caching import RedisCacheBackend


def _make_backend() -> RedisCacheBackend:
    """Create a backend instance without requiring a live Redis connection."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    return backend


def test_redis_cache_roundtrip_uses_safe_json_format():
    backend = _make_backend()
    original = {"artist": "Billie Eilish", "scores": [91.2, 87.0], "tags": ("pop", "alt")}

    encoded = backend._serialize(original)
    decoded = backend._deserialize(encoded)

    assert decoded == original


def test_redis_cache_rejects_legacy_pickle_envelope():
    backend = _make_backend()
    payload = b"not-a-safe-json-payload"
    signature = hmac.new(backend._signing_key, payload, hashlib.sha256).hexdigest()
    envelope = {
        "v": 1,
        "alg": "HMAC-SHA256",
        "sig": signature,
        "payload": base64.b64encode(payload).decode("ascii"),
    }

    encoded = json.dumps(envelope).encode("utf-8")
    assert backend._deserialize(encoded) is None
