"""Security tests for signed Redis cache payloads."""

import json
import pickle

from core.caching import RedisCacheBackend


class _DummyRedisClient:
    """Minimal Redis client stub for delete assertions."""

    def __init__(self) -> None:
        self.deleted_keys: list[str] = []

    def delete(self, key: str) -> None:
        self.deleted_keys.append(key)


def _build_backend() -> RedisCacheBackend:
    """Build a RedisCacheBackend instance without opening a real connection."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    backend._client = _DummyRedisClient()
    return backend


def test_decode_accepts_signed_payload() -> None:
    backend = _build_backend()
    original = {"artist": "A", "score": 99.1}
    encoded = backend._encode_cached_value(original)

    decoded = backend._decode_cached_value("cache:key", encoded)

    assert decoded == original
    assert backend._client.deleted_keys == []


def test_decode_rejects_tampered_payload_and_deletes_key() -> None:
    backend = _build_backend()
    encoded = backend._encode_cached_value({"safe": True})
    envelope = json.loads(encoded.decode("utf-8"))
    envelope["payload"] = envelope["payload"][:-2] + "AA"
    tampered = json.dumps(envelope).encode("utf-8")

    decoded = backend._decode_cached_value("cache:key", tampered)

    assert decoded is None
    assert backend._client.deleted_keys == ["cache:key"]


def test_decode_rejects_unsigned_legacy_pickle() -> None:
    backend = _build_backend()
    legacy_value = pickle.dumps({"legacy": "value"})

    decoded = backend._decode_cached_value("legacy:key", legacy_value)

    assert decoded is None
    assert backend._client.deleted_keys == ["legacy:key"]
