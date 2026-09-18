"""Security tests for GUI subprocess allowlisting."""

from unittest.mock import patch

import pytest

pytest.importorskip("dash")

from gui.app import _demo_argv, _run_command, _validate_command_args


class TestGuiCommandAllowlist:
    """GUI demo execution must not pass untrusted argv to subprocess."""

    def test_validate_command_args_rejects_non_strings(self):
        with pytest.raises(ValueError, match="Invalid command argument"):
            _validate_command_args([123])  # type: ignore[list-item]

    def test_validate_command_args_rejects_nul(self):
        with pytest.raises(ValueError, match="Invalid command argument"):
            _validate_command_args(["python", "main.py\x00--demo"])

    def test_run_command_returns_error_for_malformed_argv(self):
        status, output = _run_command(["python", "main.py\x00evil"])
        assert status == "Error"
        assert "Invalid command argument" in output

    def test_demo_argv_rejects_unknown_demo(self):
        with pytest.raises(ValueError, match="Invalid demo selection"):
            _demo_argv("statistical; rm -rf /")

    def test_demo_argv_allowlists_known_demos(self):
        args = _demo_argv("statistical")
        assert args[-2:] == ["--demo", "statistical"]

    def test_run_command_does_not_invoke_subprocess_for_bad_args(self):
        with patch("gui.app.subprocess.Popen") as popen:
            status, _output = _run_command([])  # type: ignore[arg-type]
            assert status == "Error"
            popen.assert_not_called()
