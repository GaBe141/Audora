"""Security tests for maintenance scripts."""

from pathlib import Path


def test_fix_linting_script_does_not_use_shell():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
    assert "list[str]" in source
