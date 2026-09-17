"""Regression tests for GUI command allowlisting."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command, run_action


def test_run_command_rejects_non_list_payload():
    status, output = _run_command("rm -rf /")  # type: ignore[arg-type]
    assert status == "Error"
    assert "Invalid command payload" in output


def test_run_command_rejects_unapproved_interpreter():
    status, output = _run_command(["/bin/sh", str(MAIN_PY), "--demo", "statistical"])
    assert status == "Error"
    assert "Unapproved interpreter" in output


def test_run_command_rejects_unapproved_binary():
    status, output = _run_command(["python", "/tmp/evil.py"])
    assert status == "Error"


def test_demo_modes_are_allowlisted():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_run_action_rejects_unapproved_demo_mode():
    mock_ctx = MagicMock()
    mock_ctx.triggered_id = "btn-demo"
    with patch("gui.app.ctx", mock_ctx):
        status, output = run_action(1, 1, None, None, "statistical; cat /etc/passwd")
    assert status == "Error"
    assert "Unapproved demo mode" in output


def test_run_action_allowlisted_demo_invokes_main_py():
    mock_ctx = MagicMock()
    mock_ctx.triggered_id = "btn-demo"
    captured: dict = {}

    def fake_run(args):
        captured["args"] = args
        return "Done (exit 0)", "ok"

    with patch("gui.app.ctx", mock_ctx), patch("gui.app._run_command", fake_run):
        status, output = run_action(None, 1, None, None, "statistical")

    assert status == "Done (exit 0)"
    assert captured["args"][1] == str(MAIN_PY)
    assert Path(captured["args"][1]).name == "main.py"
    assert captured["args"][2:] == ["--demo", "statistical"]
