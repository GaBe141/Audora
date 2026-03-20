"""Security-focused tests for Redis cache serialization."""

import base64
import json

import pandas as pd
from pandas.testing import assert_frame_equal

from core.caching import RedisCacheBackend


def _build_backend() -> RedisCacheBackend:
    """Create a RedisCacheBackend instance without network initialization."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    return backend


def test_safe_serialize_round_trip_for_dict() -> None:
    backend = _build_backend()
    original = {"name": "Audora", "enabled": True, "scores": [1, 2, 3], "meta": {"v": 1.2}}

    encoded = backend._serialize(original)
    decoded = backend._deserialize(encoded)

    assert decoded == original


def test_safe_serialize_round_trip_for_dataframe() -> None:
    backend = _build_backend()
    original = pd.DataFrame(
        {
            "track": ["Song A", "Song B"],
            "score": [92.5, 81.0],
            "platform": ["spotify", "youtube"],
        }
    )

    encoded = backend._serialize(original)
    decoded = backend._deserialize(encoded)

    assert isinstance(decoded, pd.DataFrame)
    assert_frame_equal(decoded, original)


def test_deserialize_rejects_tampered_signature() -> None:
    backend = _build_backend()
    encoded = backend._serialize({"a": 1})
    envelope = json.loads(encoded.decode("utf-8"))
    raw_payload = base64.b64decode(envelope["payload"].encode("ascii"))
    tampered_payload = raw_payload + b"x"
    envelope["payload"] = base64.b64encode(tampered_payload).decode("ascii")

    tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    assert backend._deserialize(tampered) is None
