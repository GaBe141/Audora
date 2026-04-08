"""Security tests for protected GUI callbacks and admin token validation."""

from gui.app import _validate_admin_token, run_action, save_settings


def test_validate_admin_token_requires_configured_secret(monkeypatch):
    monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)
    ok, message = _validate_admin_token("anything")
    assert ok is False
    assert "set AUDORA_GUI_ADMIN_TOKEN" in message


def test_validate_admin_token_rejects_missing_and_invalid(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected-token")

    ok_missing, message_missing = _validate_admin_token("")
    assert ok_missing is False
    assert "required" in message_missing.lower()

    ok_invalid, message_invalid = _validate_admin_token("wrong-token")
    assert ok_invalid is False
    assert "invalid" in message_invalid.lower()


def test_validate_admin_token_accepts_correct_value(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected-token")
    ok, message = _validate_admin_token("expected-token")
    assert ok is True
    assert message == ""


def test_run_action_blocks_without_valid_token(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected-token")
    status, output = run_action(None, None, None, None, "statistical", "wrong-token")
    assert status == "Forbidden"
    assert "invalid admin token" in output.lower()


def test_save_settings_blocks_without_valid_token(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "expected-token")
    result = save_settings(
        None,
        "https://example.slack",
        "https://example.discord",
        "https://example.webhook",
        "smtp.example.com",
        587,
        "user",
        "pass",
        "wrong-token",
    )
    assert "blocked" in result.lower()
