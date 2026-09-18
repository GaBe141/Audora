"""Security tests for GUI subprocess allowlisting."""

import sys
from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command, run_action


class TestGuiCommandAllowlist:
    """GUI must not pass attacker-controlled values into subprocesses."""

    def test_allowed_demo_modes_match_cli(self):
        assert ALLOWED_DEMO_MODES == {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        }

    def test_run_command_rejects_non_interpreter(self):
        status, output = _run_command(["/bin/echo", str(MAIN_PY), "--demo", "all"])
        assert status == "Error"
        assert "current Python interpreter" in output

    def test_run_command_rejects_non_main_script(self):
        status, output = _run_command([sys.executable, "/tmp/evil.py"])
        assert status == "Error"
        assert "main.py" in output

    def test_run_command_rejects_malformed_args(self):
        status, output = _run_command("not-a-list")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Malformed command" in output

    def test_run_action_rejects_invalid_demo_mode(self):
        with patch("gui.app.ctx") as mock_ctx:
            mock_ctx.triggered_id = "btn-demo"
            status, output = run_action(1, 1, 0, 0, "statistical; rm -rf /")
        assert status == "Error"
        assert output == "Invalid demo mode"

    def test_run_action_allowlisted_demo_invokes_main(self):
        with (
            patch("gui.app.ctx") as mock_ctx,
            patch("gui.app._run_command", return_value=("Done", "ok")) as mock_run,
        ):
            mock_ctx.triggered_id = "btn-demo"
            status, output = run_action(0, 1, 0, 0, "statistical")
        assert status == "Done"
        assert output == "ok"
        mock_run.assert_called_once_with(
            [sys.executable, str(MAIN_PY), "--demo", "statistical"]
        )
