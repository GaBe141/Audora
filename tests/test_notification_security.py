"""Security tests for notification webhook URL and attachment validation."""

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

    def test_rejects_hostnames_with_private_dns_results(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://example.com/webhook")

    def test_pinned_resolver_reuses_validated_addresses(self, monkeypatch):
        svc = EnhancedNotificationService()

        def fake_getaddrinfo(*_args, **_kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("93.184.216.34", 443),
                )
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        connector = svc._get_webhook_connector("https://example.com/webhook")
        try:
            resolved = connector._resolver.addresses
            assert resolved[0]["host"] == "93.184.216.34"
        finally:
            connector.close()


class TestEmailAttachmentValidation:
    """Validate that email attachments cannot exfiltrate arbitrary local files."""

    def test_allows_generated_output_attachments(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        attachment = allowed_dir / "report.json"
        attachment.write_text("{}", encoding="utf-8")

        monkeypatch.setattr(svc, "_email_attachment_base_dirs", lambda: [allowed_dir.resolve()])

        assert svc._sanitize_email_attachment(str(attachment)) == attachment.resolve()

    def test_rejects_attachments_outside_allowed_dirs(self, tmp_path, monkeypatch):
        svc = EnhancedNotificationService()
        allowed_dir = tmp_path / "data"
        allowed_dir.mkdir()
        secret_file = tmp_path / ".env"
        secret_file.write_text("SECRET=value", encoding="utf-8")

        monkeypatch.setattr(svc, "_email_attachment_base_dirs", lambda: [allowed_dir.resolve()])

        with pytest.raises(ValueError, match="outside allowed output directories"):
            svc._sanitize_email_attachment(str(secret_file))

    def test_rejects_missing_attachment(self):
        svc = EnhancedNotificationService()

        with pytest.raises(ValueError, match="does not exist"):
            svc._sanitize_email_attachment("/tmp/does-not-exist-audora")
