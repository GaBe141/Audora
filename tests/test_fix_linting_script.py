"""Security tests for the linting maintenance script."""

from pathlib import Path


def test_fix_linting_script_does_not_use_shell_true():
    script = Path(__file__).resolve().parents[1] / "scripts" / "fix_linting_issues.py"
    source = script.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
    assert "list[str]" in source
