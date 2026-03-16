"""Security regression tests for hardened configurations."""

import json
import sys
from unittest.mock import MagicMock

from core.caching import RedisCacheBackend
from integrations.api_config import SocialAPIManager

# integrations.lastfm_integration imports integrations.config; provide a tiny stub.
if "integrations.config" not in sys.modules:
    config_stub = MagicMock()
    config_stub.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = config_stub

from integrations.lastfm_integration import BASE_URL


def test_lastfm_uses_https_transport():
    """Last.fm endpoint must use TLS to protect API keys."""
    assert BASE_URL.startswith("https://")


def test_cache_payload_signature_rejects_tampering():
    """Tampered cache payloads must be discarded before deserialization."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"

    serialized = backend._serialize_value({"track": "x", "score": 99})
    envelope = json.loads(serialized.decode("utf-8"))

    # Mutate payload without recomputing signature.
    envelope["payload"] = envelope["payload"][:-2] + "AA"
    tampered = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")

    assert backend._deserialize_value(tampered) is None


def test_cache_payload_pickle_round_trip_with_signature():
    """Non-JSON objects should round-trip via signed pickle payloads."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-signing-key"

    original = {"genres": {"rock", "indie"}}
    serialized = backend._serialize_value(original)

    restored = backend._deserialize_value(serialized)
    assert restored == original


def test_social_api_config_permissions_are_restricted(tmp_path):
    """Config file containing API secrets should be mode 600 on Unix."""
    config_path = tmp_path / "social_apis.json"
    SocialAPIManager(config_file=str(config_path))

    if not sys.platform.startswith("win"):
        mode = config_path.stat().st_mode & 0o777
        assert mode == 0o600
