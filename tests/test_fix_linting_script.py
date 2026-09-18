"""Security tests for the lint auto-fix script."""

import sys
from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell():
    with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
        mock_run.return_value = None
        assert run_command([sys.executable, "-m", "black", "--help"], "help") is True
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert isinstance(args[0], list)
        assert kwargs.get("shell", False) is False
        assert args[0][0] == sys.executable
