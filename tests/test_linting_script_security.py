"""Ensure the linting maintenance script cannot invoke a shell."""

import ast
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py"


def test_linting_script_does_not_use_shell_true():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
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
    from scripts.fix_linting_issues import run_command

    annotations = run_command.__annotations__
    assert annotations["cmd"] in {list[str], "list[str]"}
