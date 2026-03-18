"""Security-focused regression tests for critical hardening changes."""

import pickle

from core.caching import CacheManager, LocalCacheBackend, RedisCacheBackend
from core.notification_service import EnhancedNotificationService


def _build_test_redis_backend() -> RedisCacheBackend:
    """Create a RedisCacheBackend instance without opening a real Redis connection."""
    backend = RedisCacheBackend.__new__(RedisCacheBackend)
    backend._signing_key = b"unit-test-cache-signing-key"
    backend._legacy_payload_warned = False
    return backend


def test_redis_cache_payload_signature_verification_rejects_tampering():
    backend = _build_test_redis_backend()
    payload = backend._serialize({"artist": "A", "score": 98.2})
    assert backend._deserialize("k1", payload) == {"artist": "A", "score": 98.2}

    # Corrupt signature while keeping payload unchanged.
    version, signature, body = payload.split(b":", 2)
    forged_prefix = b"0" if signature[:1] != b"0" else b"1"
    forged = b":".join([version, forged_prefix + signature[1:], body])
    assert backend._deserialize("k1", forged) is None


def test_redis_cache_rejects_unsigned_legacy_payloads():
    backend = _build_test_redis_backend()
    unsigned_payload = pickle.dumps({"legacy": True}, protocol=pickle.HIGHEST_PROTOCOL)
    assert backend._deserialize("legacy-key", unsigned_payload) is None


def test_cache_key_uses_sha256_not_md5():
    manager = CacheManager(backend=LocalCacheBackend(), key_prefix="test")
    key = manager._build_cache_key("fn", args=(1, 2), kwargs={"genre": "pop"})
    parts = key.split(":")

    # prefix + 2 hashes (args and kwargs), each hash should be SHA-256 hex length.
    assert parts[0] == "fn"
    assert len(parts[1]) == 64
    assert len(parts[2]) == 64


def test_webhook_url_validation_blocks_insecure_targets(monkeypatch):
    monkeypatch.delenv("AUDORA_ALLOW_INSECURE_WEBHOOKS", raising=False)
    service = EnhancedNotificationService()

    valid, error = service._validate_webhook_url("https://hooks.slack.com/services/T/B/X")
    assert valid is True
    assert error is None

    valid, error = service._validate_webhook_url("http://hooks.slack.com/services/T/B/X")
    assert valid is False
    assert "HTTPS" in (error or "")

    valid, error = service._validate_webhook_url("https://127.0.0.1/webhook")
    assert valid is False
    assert "Private or local IP" in (error or "")


def test_notification_config_saved_with_restrictive_permissions(tmp_path):
    service = EnhancedNotificationService()
    config_path = tmp_path / "config" / "notification_config.json"
    service.save_config(str(config_path))

    # chmod(600) is enforced on Unix-like systems.
    mode = config_path.stat().st_mode & 0o777
    assert mode == 0o600
