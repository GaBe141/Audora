"""Security tests for GUI admin-gated settings actions."""

import importlib

import pytest


@pytest.fixture
def gui_module(monkeypatch):
    """Load gui.app with a deterministic admin token for tests."""
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "super-secret-token")
    module = importlib.import_module("gui.app")
    return importlib.reload(module)


def test_admin_token_validator_requires_exact_match(gui_module):
    assert gui_module._is_authorized_admin_token("super-secret-token") is True
    assert gui_module._is_authorized_admin_token("wrong-token") is False
    assert gui_module._is_authorized_admin_token(None) is False


def test_save_settings_rejects_invalid_admin_token(gui_module):
    result = gui_module.save_settings(
        1,
        "https://hooks.slack.com/services/x/y/z",
        "https://discord.com/api/webhooks/x/y",
        "https://example.com/webhook",
        "smtp.example.com",
        587,
        "user@example.com",
        "smtp-pass",
        "invalid-token",
    )

    assert "Unauthorized" in result


def test_save_settings_requires_token_configuration(monkeypatch):
    monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)
    module = importlib.import_module("gui.app")
    module = importlib.reload(module)

    result = module.save_settings(
        1,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )

    assert "Security block" in result
