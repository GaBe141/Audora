"""Security tests for the lint-fix maintenance script."""

from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_lint_script_does_not_use_shell_true():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source


def test_run_command_requires_argument_list():
    assert run_command.__annotations__["cmd"] == list[str]
