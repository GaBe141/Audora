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

    def test_blocks_metadata_and_special_ranges_even_when_private_is_allowed(self):
        svc = EnhancedNotificationService()
        blocked = [
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://100.100.100.200/hook",
            "https://192.88.99.1/hook",
            "https://[::1]/hook",
            "https://[fe80::1]/hook",
            "https://[fec0::1]/hook",
            "https://[64:ff9b::1]/hook",
            "https://[2002::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://[::ffff:169.254.169.254]/hook",
            "https://[::ffff:100.100.100.200]/hook",
            "https://[fd00:ec2::254]/hook",
            "https://127.1/hook",
            "https://0177.0.0.1/hook",
            "https://0x7f.0.0.1/hook",
            "https://2130706433/hook",
        ]
        for url in blocked:
            with pytest.raises(ValueError, match="private or restricted|Localhost|Numeric"):
                svc._validate_webhook_url(url, allow_private=True)

    def test_allows_mapped_private_address_only_with_opt_in(self):
        svc = EnhancedNotificationService()
        url = "https://[::ffff:10.0.0.1]/hook"
        with pytest.raises(ValueError, match="private or restricted"):
            svc._validate_webhook_url(url, allow_private=False)
        assert svc._validate_webhook_url(url, allow_private=True) == url

    def test_rejects_userinfo_and_decimal_host_before_dns(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="userinfo"):
            svc._validate_webhook_url("https://user:pass@example.com/hook")
        with pytest.raises(ValueError, match="Numeric|private or restricted"):
            svc._validate_webhook_url("https://2130706433/hook")

    def test_smtp_port_and_metadata_host_are_rejected(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="465 or 587"):
            svc._validate_smtp_target("smtp.example.com", 25)
        with pytest.raises(ValueError, match="restricted"):
            svc._validate_smtp_target("169.254.169.254", 587)

    def test_public_addresses_stay_reachable(self):
        from core.notification_service import _address_blocked

        assert _address_blocked("1.1.1.1", allow_private=False) is False
        assert _address_blocked("8.8.8.8", allow_private=False) is False

    def test_raw_email_html_is_escaped(self):
        svc = EnhancedNotificationService()
        body = svc._html_alternative("<img src=x onerror=alert(1)>", from_template=False)
        assert "<img" not in body
        assert "&lt;img" in body

    def test_save_config_rejects_paths_outside_project(self):
        svc = EnhancedNotificationService()
        with pytest.raises(ValueError, match="project root"):
            svc.save_config("../outside.json")
        with pytest.raises(ValueError, match="project root"):
            svc.save_config("/tmp/notification_config.json")

    def test_json_helpers_refuse_symlinks(self, tmp_path):
        from core.utils import read_json, write_json

        target = tmp_path / "real.json"
        link = tmp_path / "link.json"
        target.write_text('{"ok": true}', encoding="utf-8")
        link.symlink_to(target)
        with pytest.raises(ValueError):
            read_json(link)
        with pytest.raises(ValueError):
            write_json(link, {"no": True})
