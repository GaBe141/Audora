"""Ensure maintenance scripts do not invoke a shell."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_fix_linting_issues_does_not_use_shell_true():
    source = (REPO_ROOT / "scripts" / "fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
