"""Security tests for notification webhook URL validation."""

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
    PinnedWebhookResolver,
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

    def test_rejects_shared_non_global_ip_targets_by_default(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url("https://100.64.0.1/webhook")

    def test_allows_private_ip_when_explicitly_enabled(self):
        svc = EnhancedNotificationService()
        url = "https://10.0.0.1/webhook"
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_urls_with_embedded_credentials(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="credentials"):
            svc._validate_webhook_url("https://user:pass@example.com/webhook")

    @patch("core.notification_service.socket.getaddrinfo")
    def test_validated_target_pins_checked_dns_results(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        svc = EnhancedNotificationService()

        target = svc._validated_webhook_target("https://example.com/webhook")

        assert target.url == "https://example.com/webhook"
        assert target.hostname == "example.com"
        assert target.port == 443
        assert target.resolved_ips == ("93.184.216.34",)

    @patch("core.notification_service.socket.getaddrinfo")
    def test_pinned_resolver_rejects_unvalidated_hostnames(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        svc = EnhancedNotificationService()
        target = svc._validated_webhook_target("https://example.com/webhook")
        resolver = PinnedWebhookResolver(target)

        with pytest.raises(OSError, match="Unexpected hostname"):
            asyncio.run(resolver.resolve("169.254.169.254", 443))


class TestWebhookSendingSecurity:
    """Validate outbound webhook send hardening."""

    @patch("core.notification_service.socket.getaddrinfo")
    def test_custom_webhook_send_disables_redirects(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        svc = EnhancedNotificationService()
        svc.config["webhook"]["url"] = "https://example.com/webhook"

        mock_response = MagicMock()
        mock_response.status = 204
        mock_response.__aenter__.return_value = mock_response
        mock_response.__aexit__.return_value = None

        mock_session = MagicMock()
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_session.post.return_value = mock_response

        with patch.object(svc, "_webhook_session", return_value=mock_session):
            result = asyncio.run(
                svc._send_webhook(
                    NotificationMessage(
                        title="Test",
                        content="Body",
                        priority=NotificationPriority.MEDIUM,
                        channels=[NotificationChannel.WEBHOOK],
                    )
                )
            )

        assert result == {"success": True, "status_code": 204}
        _, kwargs = mock_session.post.call_args
        assert kwargs["allow_redirects"] is False


class TestEmailHtmlEscaping:
    """Validate untrusted notification content is escaped in HTML email parts."""

    def test_email_html_part_escapes_message_content(self):
        svc = EnhancedNotificationService()
        svc.config["email"].update(
            {
                "smtp_server": "smtp.example.com",
                "recipients": ["alerts@example.com"],
                "use_tls": False,
            }
        )

        smtp = MagicMock()
        with patch("core.notification_service.smtplib.SMTP", return_value=smtp):
            result = asyncio.run(
                svc._send_email(
                    NotificationMessage(
                        title="Injected track",
                        content='</pre><a href="https://phish.example">click</a><pre>',
                        priority=NotificationPriority.HIGH,
                        channels=[NotificationChannel.EMAIL],
                    )
                )
            )

        assert result == {"success": True, "recipients": 1}
        sent_message = smtp.send_message.call_args.args[0]
        html_part = sent_message.get_payload()[1]
        html_payload = html_part.get_payload()
        assert "<a href=" not in html_payload
        assert "&lt;/pre&gt;" in html_payload
        assert "&lt;a href=&quot;https://phish.example&quot;&gt;click&lt;/a&gt;" in html_payload
