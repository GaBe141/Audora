"""Security tests for developer scripts."""

from pathlib import Path


def test_fix_linting_script_does_not_use_shell_true():
    """Ensure command execution avoids shell=True to reduce injection risk."""
    script_contents = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in script_contents
