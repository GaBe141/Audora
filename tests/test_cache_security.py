"""Security-focused tests for Redis cache serialization/deserialization."""

import base64
import json
import os

from core.caching import RedisCacheBackend


class TestRedisCacheSerializationSecurity:
    """Ensure cache serialization rejects tampered and invalid payloads."""

    def _build_backend_without_redis(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"
        return backend

    def test_rejects_tampered_signature(self):
        backend = self._build_backend_without_redis()
        serialized = backend._serialize({"safe": "value"})
        envelope = json.loads(serialized.decode("utf-8"))
        envelope["sig"] = "0" * 64
        tampered = json.dumps(envelope).encode("utf-8")

        assert backend._deserialize(tampered) is None

    def test_rejects_non_json_payload(self):
        backend = self._build_backend_without_redis()
        bad_payload = os.urandom(32)
        envelope = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "sig": "deadbeef",
            "payload": base64.b64encode(bad_payload).decode("ascii"),
        }
        serialized = json.dumps(envelope).encode("utf-8")

        assert backend._deserialize(serialized) is None

    def test_roundtrip_supports_dataframe_when_available(self):
        try:
            import pandas as pd
        except ImportError:
            return

        backend = self._build_backend_without_redis()
        frame = pd.DataFrame({"a": [1, 2], "b": ["x", "y"]})
        serialized = backend._serialize(frame)
        restored = backend._deserialize(serialized)

        assert restored is not None
        assert restored.to_dict(orient="list") == frame.to_dict(orient="list")
