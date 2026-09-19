"""Security tests for GUI subprocess allowlisting and webhook save validation."""

from gui.app import ALLOWED_DEMO_MODES, _run_command, _run_demo, save_settings


def test_demo_allowlist_matches_cli_choices():
    assert frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    ) == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command(["python", 123])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["python", "ok\x00rm"])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_empty_payload():
    status, output = _run_command([])
    assert status == "Error"


def test_run_demo_rejects_unknown_demo_mode():
    status, output = _run_demo("not-a-real-demo; rm -rf /")
    assert status == "Error"
    assert "Invalid demo mode" in output


def test_save_settings_rejects_http_webhook(monkeypatch):
    monkeypatch.setattr(
        "core.notification_service.EnhancedNotificationService.save_config",
        lambda self, path="config/notification_config.json": None,
    )
    result = save_settings(1, "http://evil.example/hook", "", "", "", "", "", "")
    assert result.startswith("Error")
