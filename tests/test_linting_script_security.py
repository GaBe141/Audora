"""Ensure the linting helper never invokes a shell."""

from pathlib import Path


def test_fix_linting_script_does_not_use_shell_true():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
    assert "subprocess.run(cmd, check=True" in source
