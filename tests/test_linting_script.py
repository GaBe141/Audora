"""Regression tests for the linting maintenance script."""

from pathlib import Path


def test_linting_script_does_not_use_shell():
    source = Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py"
    text = source.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert "sys.executable" in text
    assert "subprocess.run(cmd, check=True" in text
