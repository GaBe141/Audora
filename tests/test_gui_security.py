"""Security tests for GUI subprocess allowlisting."""

import sys
from unittest.mock import patch

from gui.app import ALLOWED_DEMO_MODES, MAIN_PY, _run_command, run_action


class TestGuiCommandAllowlist:
    """GUI subprocess execution must stay on the current interpreter and main.py."""

    def test_rejects_non_list_payload(self):
        status, output = _run_command("python evil.py")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_rejects_non_string_arguments(self):
        status, output = _run_command([sys.executable, 123])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command payload" in output

    def test_rejects_other_interpreters(self):
        status, output = _run_command(["/bin/sh", str(MAIN_PY), "--setup"])
        assert status == "Error"
        assert "current Python interpreter" in output

    def test_rejects_scripts_other_than_main(self):
        status, output = _run_command([sys.executable, "/tmp/evil.py"])
        assert status == "Error"
        assert "main.py" in output

    def test_allowlisted_demo_modes_match_cli(self):
        assert ALLOWED_DEMO_MODES == {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        }

    def test_invalid_demo_mode_is_rejected(self):
        with patch("gui.app.ctx") as mock_ctx:
            mock_ctx.triggered_id = "btn-demo"
            status, output = run_action(1, 1, 0, 0, "--help; cat /etc/passwd")
        assert status == "Error"
        assert output == "Invalid demo mode"

    def test_valid_demo_mode_invokes_main(self):
        with (
            patch("gui.app.ctx") as mock_ctx,
            patch("gui.app._run_command", return_value=("Done (exit 0)", "ok")) as mock_run,
        ):
            mock_ctx.triggered_id = "btn-demo"
            status, output = run_action(0, 1, 0, 0, "statistical")
        assert status == "Done (exit 0)"
        assert output == "ok"
        mock_run.assert_called_once_with(
            [sys.executable, str(MAIN_PY), "--demo", "statistical"]
        )
