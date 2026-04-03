"""Tests for critical security hardening controls."""

from pathlib import Path

import pytest

from core.notification_service import EnhancedNotificationService


def test_save_config_strips_sensitive_fields(tmp_path: Path):
    """Config persistence must not write secrets to disk."""
    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "super-secret-password"
    svc.config["sms"]["api_key"] = "sms-key"
    svc.config["sms"]["api_secret"] = "sms-secret"
    svc.config["webhook"]["headers"]["Authorization"] = "Bearer token"
    svc.config["webhook"]["headers"]["X-API-Key"] = "api-key"
    svc.config["webhook"]["headers"]["Content-Type"] = "application/json"

    out_path = tmp_path / "notification_config.json"
    svc.save_config(str(out_path))

    saved = out_path.read_text(encoding="utf-8")
    assert "super-secret-password" not in saved
    assert "sms-key" not in saved
    assert "sms-secret" not in saved
    assert "Bearer token" not in saved
    assert "api-key" not in saved
    # Non-sensitive header is still persisted.
    assert "Content-Type" in saved


def test_save_config_does_not_mutate_runtime_secrets(tmp_path: Path):
    """Sanitization should affect persisted copy, not in-memory runtime config."""
    svc = EnhancedNotificationService()
    svc.config["email"]["password"] = "runtime-secret"
    out_path = tmp_path / "notification_config.json"
    svc.save_config(str(out_path))
    assert svc.config["email"]["password"] == "runtime-secret"


def test_is_loopback_client_accepts_loopback_variants():
    """Loopback identification should handle IPv4, IPv6, and IPv6 scope IDs."""
    _is_loopback_client = pytest.importorskip("gui.app")._is_loopback_client
    assert _is_loopback_client("127.0.0.1") is True
    assert _is_loopback_client("::1") is True
    assert _is_loopback_client("::1%lo0") is True


def test_is_loopback_client_rejects_non_loopback_addresses():
    """Only localhost/loopback addresses should bypass remote GUI checks."""
    _is_loopback_client = pytest.importorskip("gui.app")._is_loopback_client
    assert _is_loopback_client("192.168.1.50") is False
    assert _is_loopback_client("10.0.0.1") is False
    assert _is_loopback_client(None) is False
