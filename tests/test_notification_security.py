"""Security tests for notification webhook and attachment validation."""

import asyncio
import socket

import pytest

from core.notification_service import EnhancedNotificationService


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

    def test_pins_connector_to_prevalidated_dns_result(self, monkeypatch):
        svc = EnhancedNotificationService()
        calls = 0

        def fake_getaddrinfo(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("93.184.216.34", 443),
                    )
                ]
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", 443),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        async def prepare_request():
            return svc._prepare_webhook_request("https://example.com/webhook")

        async def close_connector():
            await connector.close()

        url, connector = asyncio.run(prepare_request())

        assert url == "https://example.com/webhook"
        assert connector._resolver.resolved_ips == {"93.184.216.34"}
        assert calls == 1
        asyncio.run(close_connector())


class TestEmailAttachmentValidation:
    """Validate file disclosure protections for email attachments."""

    def test_rejects_attachment_outside_allowed_directory(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_root = tmp_path / "attachments"
        allowed_root.mkdir()
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("secret", encoding="utf-8")
        monkeypatch.setenv("AUDORA_NOTIFICATION_ATTACHMENT_DIR", str(allowed_root))

        with pytest.raises(ValueError, match="inside allowed directory"):
            svc._validate_attachment_path(str(secret_file))

    def test_allows_attachment_inside_allowed_directory(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_root = tmp_path / "attachments"
        allowed_root.mkdir()
        report_file = allowed_root / "report.txt"
        report_file.write_text("safe", encoding="utf-8")
        monkeypatch.setenv("AUDORA_NOTIFICATION_ATTACHMENT_DIR", str(allowed_root))

        assert svc._validate_attachment_path(str(report_file)) == report_file.resolve()
