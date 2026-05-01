"""Security tests for the lint-fixing helper script."""

from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_does_not_use_shell():
    """Helper commands must not be routed through a shell."""
    command = ["python", "-m", "ruff", "check", "core/caching.py"]

    with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
        assert run_command(command, "test command") is True

    mock_run.assert_called_once_with(command, check=True, capture_output=True, text=True)
