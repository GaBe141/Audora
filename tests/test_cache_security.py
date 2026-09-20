"""Security tests for Redis cache serialization envelopes."""

import base64
import hashlib
import hmac
import json
import pickle

import pandas as pd
import pytest

from core.caching import RedisCacheBackend


def _codec(key: bytes = b"unit-test-signing-key") -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = key
    backend._key_prefix = "audora"
    return backend


class TestRedisJsonEnvelope:
    """Signed JSON envelopes must round-trip and reject pickle/legacy payloads."""

    def test_roundtrip_json_value(self):
        backend = _codec()
        payload = backend._serialize({"track": "Song", "score": 91})
        assert b"pickle" not in payload.lower()
        assert backend._deserialize(payload) == {"track": "Song", "score": 91}

    def test_roundtrip_dataframe(self):
        backend = _codec()
        df = pd.DataFrame({"track": ["a"], "score": [1.5]})
        restored = backend._deserialize(backend._serialize(df))
        assert list(restored.columns) == ["track", "score"]
        assert restored.iloc[0]["track"] == "a"
        assert float(restored.iloc[0]["score"]) == pytest.approx(1.5)

    def test_rejects_legacy_pickle_envelope(self):
        backend = _codec()
        pickled = pickle.dumps({"pwn": True})
        signature = hmac.new(backend._signing_key, pickled, hashlib.sha256).hexdigest()
        envelope = json.dumps(
            {
                "v": 1,
                "alg": "HMAC-SHA256",
                "sig": signature,
                "payload": base64.b64encode(pickled).decode("ascii"),
            }
        ).encode("utf-8")
        assert backend._deserialize(envelope) is None

    def test_rejects_tampered_signature(self):
        backend = _codec()
        envelope = json.loads(backend._serialize("ok").decode("utf-8"))
        envelope["sig"] = "0" * 64
        assert backend._deserialize(json.dumps(envelope).encode("utf-8")) is None

    def test_roundtrip_tuple(self):
        backend = _codec()
        assert backend._deserialize(backend._serialize((1, "a"))) == (1, "a")

    def test_rejects_unsupported_types(self):
        backend = _codec()
        with pytest.raises(TypeError, match="Cannot safely cache"):
            backend._serialize(object())
