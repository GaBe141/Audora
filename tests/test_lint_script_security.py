"""Ensure the lint helper cannot invoke a shell."""

import ast
import inspect
from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_lint_script_has_no_shell_true():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                assert keyword.value.value is not True


def test_run_command_accepts_argument_lists_only():
    signature = inspect.signature(run_command)
    cmd_annotation = signature.parameters["cmd"].annotation
    assert cmd_annotation == list[str]
