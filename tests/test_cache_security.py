"""Security-focused tests for Redis cache serialization safeguards."""

import json

import pytest

from core.caching import RedisCacheBackend


class TestRedisCacheSecurity:
    """Ensure Redis cache rejects tampered and unsupported payloads safely."""

    def test_deserialize_rejects_tampered_signature(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        envelope = {
            "v": 2,
            "alg": "HMAC-SHA256",
            "ser": "json-safe-v1",
            "sig": "bad-signature",
            "payload": {"t": "primitive", "v": "safe"},
        }

        serialized = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
        assert backend._deserialize(serialized) is None

    def test_encode_safe_value_rejects_non_string_dict_keys(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        with pytest.raises(TypeError, match="string keys"):
            backend._encode_safe_value({1: "x"})

