"""Security tests for the lint auto-fix maintenance script."""

from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_rejects_empty_or_invalid_argv():
    assert run_command([], "empty") is False
    assert run_command(["echo", "x\x00y"], "nul") is False


def test_run_command_invokes_subprocess_without_shell():
    with patch("scripts.fix_linting_issues.subprocess.run") as mocked:
        mocked.return_value = None
        assert run_command(["python", "-m", "ruff", "check", "core/caching.py"], "ruff") is True
        mocked.assert_called_once()
        args, kwargs = mocked.call_args
        assert args[0] == ["python", "-m", "ruff", "check", "core/caching.py"]
        assert kwargs.get("shell", False) is False
