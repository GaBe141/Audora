"""Regression tests for critical security hardening."""

import asyncio
from pathlib import Path

import pytest

from core.notification_service import (
    EnhancedNotificationService,
    NotificationChannel,
    NotificationMessage,
    NotificationPriority,
)
from integrations.social_discovery_engine import SocialMusicDiscoveryEngine


class TestNotificationSecurityHardening:
    """Validate outbound notification security checks."""

    def test_url_validator_blocks_local_and_insecure_targets(self):
        service = EnhancedNotificationService()

        assert not service._is_safe_outbound_url("http://127.0.0.1/hook")
        assert not service._is_safe_outbound_url("https://localhost/hook")
        assert not service._is_safe_outbound_url("https://10.0.0.5/hook")
        assert service._is_safe_outbound_url("https://1.1.1.1/hook")

    def test_send_webhook_rejects_blocked_url_without_network(self):
        service = EnhancedNotificationService()
        service.config["webhook"]["url"] = "https://127.0.0.1/hook"

        message = NotificationMessage(
            title="Security test",
            content="Should be blocked before network call",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.WEBHOOK],
        )

        result = asyncio.run(service._send_webhook(message))
        assert result["success"] is False
        assert "blocked by security policy" in result["error"]


class TestReportPathTraversalHardening:
    """Validate report write path restrictions."""

    def test_social_engine_blocks_path_traversal(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        engine = SocialMusicDiscoveryEngine(config={})

        with pytest.raises(ValueError, match="Unsafe report path"):
            engine.save_discovery_report({"ok": True}, "../outside.json")

    def test_social_engine_allows_data_subpath(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        engine = SocialMusicDiscoveryEngine(config={})

        saved = engine.save_discovery_report({"ok": True}, "data/reports/safe_report.json")
        saved_path = Path(saved).resolve()
        assert saved_path.exists()
        assert saved_path.is_relative_to((tmp_path / "data").resolve())
