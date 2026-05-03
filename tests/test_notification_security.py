"""Security tests for notification webhook URL validation."""

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

    def test_webhook_requests_do_not_follow_redirects(self):
        svc = EnhancedNotificationService()
        assert svc._webhook_request_options()["allow_redirects"] is False


class TestEmailAttachmentValidation:
    """Validate restrictions for notification email attachments."""

    def test_rejects_attachment_outside_allowed_roots(self, tmp_path):
        svc = EnhancedNotificationService()
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("secret", encoding="utf-8")
        svc.config["attachments"]["allowed_roots"] = [str(safe_root)]

        with pytest.raises(ValueError, match="outside the allowed attachment directories"):
            svc._resolve_attachment_path(str(secret_file))

    def test_allows_attachment_inside_allowed_root(self, tmp_path):
        svc = EnhancedNotificationService()
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        report_file = safe_root / "report.txt"
        report_file.write_text("ok", encoding="utf-8")
        svc.config["attachments"]["allowed_roots"] = [str(safe_root)]

        assert svc._resolve_attachment_path(str(report_file)) == report_file.resolve()

    def test_rejects_oversized_attachment(self, tmp_path):
        svc = EnhancedNotificationService()
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        report_file = safe_root / "report.txt"
        report_file.write_text("too large", encoding="utf-8")
        svc.config["attachments"]["allowed_roots"] = [str(safe_root)]
        svc.config["attachments"]["max_bytes"] = 2

        with pytest.raises(ValueError, match="exceeds maximum size"):
            svc._resolve_attachment_path(str(report_file))

    def test_rejects_attachment_symlink_escape(self, tmp_path):
        svc = EnhancedNotificationService()
        safe_root = tmp_path / "safe"
        safe_root.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret", encoding="utf-8")
        symlink_path = safe_root / "escaped.txt"
        symlink_path.symlink_to(outside_file)
        svc.config["attachments"]["allowed_roots"] = [str(safe_root)]

        with pytest.raises(ValueError, match="outside the allowed attachment directories"):
            svc._resolve_attachment_path(str(symlink_path))
