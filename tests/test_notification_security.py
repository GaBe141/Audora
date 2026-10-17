"""Security tests for notification webhook URL validation."""

import asyncio
import smtplib
import socket

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)


class TestWebhookUrlValidation:
    """Validate SSRF protections for outbound webhooks."""

    def test_rejects_non_https_urls(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="HTTPS"):
            svc._validate_webhook_url("http://example.com/webhook")

    def test_rejects_localhost_targets(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_webhook_url("https://localhost/webhook")

    def test_rejects_private_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://10.0.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_cgnat_even_when_private_webhooks_are_enabled(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.100.100.200/hook", allow_private=True)

    def test_rejects_decimal_and_obfuscated_loopback_hosts(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://2130706433/hook",
            "https://127.1/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
        ):
            with pytest.raises(ValueError):
                svc._validate_webhook_url(url, allow_private=True)

    def test_rejects_userinfo_and_mapped_loopback(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://[::ffff:127.0.0.1]/hook", allow_private=True)

    def test_allows_mapped_private_address_when_opted_in(self):
        svc = EnhancedNotificationService()
        url = "https://[::ffff:10.0.0.1]/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_metadata_ranges_explicitly(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://192.88.99.1/hook",
            "https://[fec0::1]/hook",
            "https://[fd00:ec2::254]/hook",
            "https://[64:ff9b::1]/hook",
            "https://[2002::1]/hook",
            "https://[2001::1]/hook",
        ):
            with pytest.raises(ValueError, match="private or restricted"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_save_config_rejects_absolute_path(self, tmp_path):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="relative"):
            svc.save_config(str(tmp_path / "notification_config.json"))

    def test_smtp_pins_resolved_address_and_rejects_metadata(self, monkeypatch):
        svc = EnhancedNotificationService()

        def public_dns(host, _port, *args, **kwargs):
            assert host == "smtp.example.com"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", public_dns)
        assert svc._validate_smtp_host("smtp.example.com") == "smtp.example.com"
        assert svc._pinned_smtp_connect_host("smtp.example.com") == "1.1.1.1"

        def metadata_dns(host, _port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", metadata_dns)
        with pytest.raises(ValueError, match="restricted"):
            svc._validate_smtp_host("smtp.example.com")

    def test_send_email_connects_to_pinned_address(self, monkeypatch):
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["recipients"] = ["listener@example.com"]
        svc.config["email"]["port"] = 587
        svc.config["email"]["username"] = ""
        svc.config["email"]["password"] = ""

        def public_dns(host, _port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", public_dns)
        calls: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, timeout: int = 30) -> None:
                self._host = ""

            def connect(self, host: str, port: int) -> tuple[int, bytes]:
                calls["host"] = host
                calls["port"] = port
                calls["tls_name"] = self._host
                return (220, b"ok")

            def starttls(self, context: object = None) -> tuple[int, bytes]:
                return (220, b"tls")

            def ehlo(self) -> tuple[int, bytes]:
                return (250, b"ehlo")

            def send_message(self, message: object) -> dict[str, object]:
                return {}

            def quit(self) -> tuple[int, bytes]:
                return (221, b"bye")

            def close(self) -> None:
                return None

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        message = NotificationMessage(
            title="Alert",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[NotificationChannel.EMAIL],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert calls["host"] == "1.1.1.1"
        assert calls["tls_name"] == "smtp.example.com"

    def test_smtp_rejects_private_and_teredo_targets(self, monkeypatch):
        svc = EnhancedNotificationService()
        for host in ("10.0.0.1", "2001::1", "fd00::1", "::ffff:10.0.0.1"):
            with pytest.raises(ValueError, match="restricted"):
                svc._validate_smtp_host(host)

        def private_dns(host, _port, *args, **kwargs):
            assert host == "smtp.example.com"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", private_dns)
        with pytest.raises(ValueError, match="restricted"):
            svc._validate_smtp_host("smtp.example.com")

    def test_smtp_rfc1918_opt_in_still_blocks_tunnels(self, monkeypatch):
        monkeypatch.setenv("AUDORA_ALLOW_PRIVATE_SMTP", "1")
        svc = EnhancedNotificationService()
        assert svc._validate_smtp_host("10.0.0.1") == "10.0.0.1"
        assert svc._pinned_smtp_connect_host("10.0.0.1") == "10.0.0.1"
        for host in ("2001::1", "169.254.169.254", "100.100.100.200", "fd00::1"):
            with pytest.raises(ValueError, match="restricted"):
                svc._validate_smtp_host(host)
