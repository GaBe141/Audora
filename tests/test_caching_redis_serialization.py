"""Tests for secure Redis cache serialization/deserialization behavior."""

import json

import pytest

from core.caching import RedisCacheBackend


class _DummyRedisClient:
    """Tiny in-memory Redis stub for unit testing RedisCacheBackend."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def set(self, key: str, value: bytes) -> None:
        self.store[key] = value

    def setex(self, key: str, _ttl: int, value: bytes) -> None:
        self.store[key] = value

    def delete(self, key: str) -> None:
        self.store.pop(key, None)


def _backend_with_dummy_client() -> tuple[RedisCacheBackend, _DummyRedisClient]:
    backend = object.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"
    client = _DummyRedisClient()
    backend._client = client
    return backend, client


def test_redis_backend_roundtrip_json_value() -> None:
    backend, _client = _backend_with_dummy_client()
    key = "k:json"
    value = {"a": 1, "b": ["x", "y"]}
    backend.set(key, value, ttl=10)
    assert backend.get(key) == value


def test_redis_backend_roundtrip_bytes_value() -> None:
    backend, _client = _backend_with_dummy_client()
    key = "k:bytes"
    value = b"\x01\x02\x03binary"
    backend.set(key, value, ttl=10)
    assert backend.get(key) == value


def test_redis_backend_rejects_unsupported_value_type() -> None:
    backend, _client = _backend_with_dummy_client()

    with pytest.raises(TypeError, match="Unsupported cache value type"):
        backend._serialize({"bad": {1, 2, 3}})


def test_redis_backend_rejects_tampered_payload_and_deletes_key() -> None:
    backend, client = _backend_with_dummy_client()
    key = "k:tampered"
    backend.set(key, {"safe": True}, ttl=10)
    raw = client.get(key)
    assert raw is not None

    envelope = json.loads(raw.decode("utf-8"))
    envelope["payload"] = "eyJ0eXBlIjoianNvbiIsImRhdGEiOiJ7XCJvd25lZFwiOnRydWV9In0="
    client.set(key, json.dumps(envelope).encode("utf-8"))

    assert backend.get(key) is None
    assert client.get(key) is None
