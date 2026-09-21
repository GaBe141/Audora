"""Security checks for GUI callbacks that accept external input."""

from unittest.mock import patch

from gui.app import export_csv, run_action, save_settings


def test_demo_mode_is_allowlisted():
    with patch("gui.app.ctx") as callback_context:
        callback_context.triggered_id = "btn-demo"
        status, output = run_action(None, 1, None, None, "--help")
    assert status == "Error"
    assert "Unsupported demo" in output


def test_save_settings_rejects_cleartext_webhook():
    status = save_settings(
        1,
        None,
        None,
        "http://127.0.0.1/hook",
        None,
        None,
        None,
        None,
    )
    assert "HTTPS" in status


def test_history_export_neutralizes_formulas():
    payload = export_csv(1, [{"track": "=1+1", "artist": "Ada"}])
    content = payload["content"]
    assert "'=1+1" in content
