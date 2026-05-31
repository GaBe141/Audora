"""Security tests for notification webhook URL validation."""

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

    def test_rejects_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="embedded credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    def test_webhook_connector_pins_validated_dns_results(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(host, port, proto=0):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    proto,
                    "",
                    ("93.184.216.34", port),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        async def create_resolve_and_close():
            url, connector = svc._create_webhook_connector("https://example.com/webhook")
            try:
                resolved = await connector._resolver.resolve("example.com", 443)
            finally:
                await connector.close()
            return url, resolved

        url, resolved = asyncio.run(create_resolve_and_close())

        assert url == "https://example.com/webhook"
        assert resolved[0]["host"] == "93.184.216.34"


class TestEmailAttachmentValidation:
    """Validate that email attachments cannot read arbitrary files."""

    def test_allows_attachment_inside_configured_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        svc.config["email"]["attachments_dir"] = str(tmp_path)
        attachment = tmp_path / "report.txt"
        attachment.write_text("safe", encoding="utf-8")

        assert svc._resolve_attachment_path(str(attachment)) == attachment

    def test_rejects_attachment_outside_configured_directory(self, tmp_path):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("do not attach", encoding="utf-8")
        svc.config["email"]["attachments_dir"] = str(allowed_dir)

        with pytest.raises(ValueError, match="attachments directory"):
            svc._resolve_attachment_path(str(secret_file))
