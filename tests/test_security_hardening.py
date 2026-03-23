"""Security hardening tests for cache and notification protections."""

import hashlib
import hmac
import json

import pytest

from core.caching import RedisCacheBackend
from core.notification_service import EnhancedNotificationService


def _build_backend() -> RedisCacheBackend:
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"test-signing-key"
    return backend


def test_cache_serialization_round_trip_safe_types():
    backend = _build_backend()
    payload = {
        "artist": "Sample Artist",
        "scores": [1, 2, 3],
        "tags": {"a", "b"},
        "meta": ("x", 2),
        "raw": b"bytes",
    }

    encoded = backend._serialize(payload)
    restored = backend._deserialize(encoded)

    assert isinstance(restored, dict)
    assert restored["artist"] == "Sample Artist"
    assert restored["scores"] == [1, 2, 3]
    assert restored["tags"] == {"a", "b"}
    assert restored["meta"] == ("x", 2)
    assert restored["raw"] == b"bytes"


def test_cache_deserialization_rejects_legacy_format():
    backend = _build_backend()
    payload = b"{}"
    signature = hmac.new(backend._signing_key, payload, hashlib.sha256).hexdigest()
    legacy_envelope = {
        "v": 1,
        "alg": "HMAC-SHA256",
        "sig": signature,
        "payload": "e30=",  # base64 for {}
    }

    assert backend._deserialize(json.dumps(legacy_envelope).encode("utf-8")) is None


def test_cache_rejects_unsupported_type():
    backend = _build_backend()

    class Unsupported:
        pass

    with pytest.raises(TypeError, match="Unsupported cache value type"):
        backend._serialize(Unsupported())


def test_private_webhook_toggle_requires_explicit_ack(monkeypatch):
    monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "true")
    monkeypatch.delenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS_ACK", raising=False)
    svc = EnhancedNotificationService()
    assert svc._allow_private_webhooks() is False

    monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS_ACK", "I_UNDERSTAND_SSRF_RISK")
    assert svc._allow_private_webhooks() is True


def test_persisted_config_sanitizes_secrets():
    svc = EnhancedNotificationService()
    sanitized = svc._sanitize_persisted_config(
        {
            "email": {"smtp_server": "smtp.example.com", "password": "secret"},
            "sms": {"api_key": "api-key", "api_secret": "api-secret"},
            "webhook": {
                "url": "https://example.com/hook",
                "headers": {"Authorization": "Bearer secret", "Content-Type": "application/json"},
            },
        }
    )

    assert "password" not in sanitized["email"]
    assert "api_key" not in sanitized["sms"]
    assert "api_secret" not in sanitized["sms"]
    assert "Authorization" not in sanitized["webhook"]["headers"]
