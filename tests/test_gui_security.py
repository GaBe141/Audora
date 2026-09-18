"""Security tests for GUI subprocess orchestration."""

import sys
from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, PROJECT_ROOT, _run_command, run_action


class TestGuiCommandAllowlist:
    """GUI must not pass client-controlled values into arbitrary subprocesses."""

    def test_allowed_demo_modes_match_cli(self):
        assert {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        } == ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_main_payload(self):
        status, output = _run_command(["/bin/echo", "pwned"])
        assert status == "Error"
        assert "main.py" in output

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command("echo pwned")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_invalid_demo_mode_does_not_spawn(self):
        with patch("gui.app._run_command") as run_command, patch("gui.app.ctx") as fake_ctx:
            fake_ctx.triggered_id = "btn-demo"
            status, output = run_action(1, 1, None, None, "; rm -rf /")
        run_command.assert_not_called()
        assert status == "Error"
        assert output == "Invalid demo mode"

    def test_valid_demo_mode_uses_current_interpreter(self):
        with patch("gui.app._run_command", return_value=("Done", "ok")) as run_command, patch(
            "gui.app.ctx"
        ) as fake_ctx:
            fake_ctx.triggered_id = "btn-demo"
            status, output = run_action(1, 1, None, None, "statistical")
        run_command.assert_called_once_with(
            [sys.executable, str(PROJECT_ROOT / "main.py"), "--demo", "statistical"]
        )
        assert status == "Done"
        assert output == "ok"
