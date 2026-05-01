"""Security regression tests for the automated lint-fix helper."""

from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell():
    """Commands should not be routed through a shell."""
    with patch("scripts.fix_linting_issues.subprocess.run") as run_mock:
        assert run_command(["python", "-m", "ruff", "check"], "test command") is True

    run_mock.assert_called_once_with(
        ["python", "-m", "ruff", "check"],
        check=True,
        capture_output=True,
        text=True,
    )
