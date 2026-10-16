"""Security tests for notification webhook URL validation."""

import asyncio

import pytest

from core.notification_service import (
    EnhancedNotificationService,
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

    @pytest.mark.parametrize(
        "url",
        [
            "https://100.100.100.200/hook",
            "https://100.64.0.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[64:ff9b::a9fe:a9fe]/hook",
            "https://[64:ff9b::7f00:1]/hook",
            "https://[fec0::1]/hook",
            "https://192.88.99.1/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://[::ffff:169.254.169.254]/hook",
            "https://[::]/hook",
        ],
    )
    def test_rejects_metadata_and_transition_ranges(self, url):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url)

    def test_private_opt_in_still_blocks_metadata(self):
        svc = EnhancedNotificationService()
        for url in (
            "https://169.254.169.254/hook",
            "https://100.100.100.200/hook",
            "https://[64:ff9b::a9fe:a9fe]/hook",
        ):
            with pytest.raises(ValueError, match="private or restricted"):
                svc._validate_webhook_url(url, allow_private=True)

    @pytest.mark.parametrize(
        "url",
        [
            "https://127.1/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
            "https://2130706433/hook",
            "https://user:pass@example.com/hook",
            "https://127.0.0.1/hook",
            "http://example.com/hook",
        ],
    )
    def test_rejects_obfuscated_and_credentialed_targets(self, url):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError):
            svc._validate_webhook_url(url)

    def test_rejects_localhost_smtp(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="Localhost"):
            svc._validate_smtp_host("localhost")

    def test_rejects_loopback_smtp_ip(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_smtp_host("127.0.0.1")

    def test_starttls_checks_the_validated_hostname(self, monkeypatch):
        """STARTTLS must verify the certificate name, not an empty SMTP._host."""
        svc = EnhancedNotificationService()
        svc.config["email"]["smtp_server"] = "smtp.example.com"
        svc.config["email"]["port"] = 587
        svc.config["email"]["username"] = ""
        svc.config["email"]["password"] = ""
        svc.config["email"]["recipients"] = ["ops@example.com"]
        captured: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, pinned_ip: str, timeout: int = 30) -> None:
                self._host = ""
                captured["pinned_ip"] = pinned_ip

            def connect(self, host: str, port: int):
                captured["host_at_connect"] = self._host
                captured["port"] = port
                return (220, b"ok")

            def ehlo(self):
                return (250, b"ok")

            def starttls(self, context=None):
                captured["host_at_starttls"] = self._host
                return (220, b"ok")

            def send_message(self, msg):
                return {}

            def quit(self):
                return None

        monkeypatch.setattr(
            "core.notification_service._PinnedSMTP",
            FakeSMTP,
        )
        monkeypatch.setattr(
            svc,
            "_validate_smtp_host",
            lambda host, allow_private=None: ("smtp.example.com", ("1.1.1.1",)),
        )
        message = NotificationMessage(
            title="Status",
            content="hello",
            priority=NotificationPriority.LOW,
            channels=[],
        )
        result = asyncio.run(svc._send_email(message))
        assert result["success"] is True
        assert captured["pinned_ip"] == "1.1.1.1"
        assert captured["host_at_connect"] == "smtp.example.com"
        assert captured["host_at_starttls"] == "smtp.example.com"
        assert captured["port"] == 587
