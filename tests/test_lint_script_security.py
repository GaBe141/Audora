"""Ensure the maintenance script cannot spawn a shell."""

import ast
from pathlib import Path


def test_fix_linting_script_does_not_use_shell_true():
    script = Path(__file__).resolve().parents[1] / "scripts" / "fix_linting_issues.py"
    tree = ast.parse(script.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                raise AssertionError("scripts/fix_linting_issues.py must not use shell=True")


def test_fix_linting_run_command_requires_argument_list():
    script = Path(__file__).resolve().parents[1] / "scripts" / "fix_linting_issues.py"
    source = script.read_text(encoding="utf-8")
    assert "def run_command(cmd: list[str]" in source
    assert "sys.executable" in source
