"""Security tests for the automated lint fixing helper."""

from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell():
    with patch("scripts.fix_linting_issues.subprocess.run") as run:
        assert run_command(["python", "-m", "ruff", "check", "core"], "ruff") is True

    assert run.call_args.args[0] == ["python", "-m", "ruff", "check", "core"]
    assert "shell" not in run.call_args.kwargs
