"""Security regression tests for scripts/fix_linting_issues.py."""

from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell() -> None:
    """Ensure run_command executes argv directly (no shell interpretation)."""
    cmd = ["python3", "-c", "print('ok')"]
    with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
        mock_run.return_value = None
        assert run_command(cmd, "test command")

    mock_run.assert_called_once_with(cmd, check=True, capture_output=True, text=True)


def test_run_command_preserves_shell_metacharacters_as_literals() -> None:
    """Command strings with metacharacters should remain plain arguments."""
    cmd = ["echo", "safe; rm -rf /"]
    with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
        mock_run.return_value = None
        assert run_command(cmd, "literal metacharacters")

    called_cmd = mock_run.call_args.kwargs.get("args", mock_run.call_args.args[0])
    assert called_cmd == cmd
