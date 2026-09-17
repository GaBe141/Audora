"""Security tests for the maintenance lint-fix script."""

import ast
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py"


def test_linting_script_does_not_use_shell_true():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                raise AssertionError("shell=True is not allowed in fix_linting_issues.py")


def test_run_command_requires_argument_list():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "def run_command(cmd: list[str]" in source
    assert "sys.executable" in source
