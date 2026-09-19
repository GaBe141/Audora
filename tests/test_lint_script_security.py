"""Ensure the lint helper never shells out with a command string."""

import ast
from pathlib import Path


def test_fix_linting_issues_does_not_use_shell_true():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                assert keyword.value.value is not True
