"""Security checks for GUI notification settings helpers."""

import pytest

pytest.importorskip("dash")
pytest.importorskip("dash_bootstrap_components")

from core.notification_service import EnhancedNotificationService
from gui.app import _set_validated_webhook_urls, save_settings


def test_gui_rejects_private_slack_webhook_url():
    svc = EnhancedNotificationService()

    with pytest.raises(ValueError, match="private or restricted"):
        _set_validated_webhook_urls(svc, "https://10.0.0.1/webhook", None, None)


def test_gui_rejects_smtp_password_persistence():
    result = save_settings(
        1,
        None,
        None,
        None,
        "smtp.example.com",
        587,
        "audora",
        "smtp-secret",
    )

    assert "SMTP_PASSWORD" in result
