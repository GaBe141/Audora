"""Ensure the lint fixer never shells out with shell=True."""

import ast
from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_lint_script_does_not_use_shell_true():
    source_path = Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = ""
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name not in {"run", "Popen", "call", "check_call", "check_output"}:
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                assert keyword.value.value is not True
        if node.args:
            assert not isinstance(node.args[0], ast.JoinedStr)


def test_run_command_expects_argument_list():
    annotations = run_command.__annotations__
    assert annotations["args"] == list[str]
