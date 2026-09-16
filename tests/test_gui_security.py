"""Security tests for GUI command construction."""

from types import SimpleNamespace
from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, _run_command, run_action


def test_demo_allowlist_matches_cli_choices():
    assert frozenset(
        {"statistical", "trending", "multi_source", "platform", "all"}
    ) == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command(["python", 1])  # type: ignore[list-item]
    assert status == "Error"
    assert "list of strings" in output


def test_run_action_rejects_unknown_demo_mode():
    fake_ctx = SimpleNamespace(triggered_id="btn-demo")
    with patch("gui.app.ctx", fake_ctx):
        status, output = run_action(1, 1, None, None, "statistical; rm -rf /")
    assert status == "Error"
    assert output == "Invalid demo mode"
