"""Security tests for Redis cache serialization and integrity checks."""

import base64
import hmac
import json

from core.caching import RedisCacheBackend


def _build_signed_envelope(
    backend: RedisCacheBackend, payload_obj: object, *, version: int | None = None
) -> bytes:
    payload = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(backend._signing_key, payload, "sha256").hexdigest()  # noqa: SLF001
    envelope = {
        "v": backend._SERIALIZATION_VERSION if version is None else version,  # noqa: SLF001
        "alg": "HMAC-SHA256",
        "sig": signature,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


class TestRedisCacheSerializationSecurity:
    """Ensure Redis cache rejects malformed or unsafe payloads."""

    def test_round_trip_for_supported_values(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        value = {
            "message": "ok",
            "count": 7,
            "flags": [True, False],
            "nested": {"a": 1, "b": "two"},
            "blob": b"\x00\x01\x02",
            "coords": (1, 2),
        }

        serialized = backend._serialize(value)
        deserialized = backend._deserialize(serialized)

        assert deserialized is not None
        assert deserialized["message"] == value["message"]
        assert deserialized["count"] == value["count"]
        assert deserialized["flags"] == value["flags"]
        assert deserialized["nested"] == value["nested"]
        assert deserialized["blob"] == value["blob"]
        assert deserialized["coords"] == value["coords"]

    def test_rejects_tampered_signed_payload(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        original_payload = {"safe": True}
        signed = _build_signed_envelope(backend, original_payload)
        envelope = json.loads(signed.decode("utf-8"))

        tampered_payload = {"safe": False, "attack": "tamper"}
        tampered_payload_bytes = json.dumps(
            tampered_payload, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        envelope["payload"] = base64.b64encode(tampered_payload_bytes).decode("ascii")
        tampered_envelope = json.dumps(envelope, separators=(",", ":")).encode("utf-8")

        assert backend._deserialize(tampered_envelope) is None

    def test_rejects_legacy_version_to_block_pickle_envelopes(self):
        backend = RedisCacheBackend.__new__(RedisCacheBackend)
        backend._signing_key = b"test-signing-key"

        legacy_payload = {"legacy": "data"}
        legacy_envelope = _build_signed_envelope(backend, legacy_payload, version=1)

        assert backend._deserialize(legacy_envelope) is None

