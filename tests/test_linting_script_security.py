"""Security tests for maintenance scripts."""

import ast
from pathlib import Path


def test_fix_linting_issues_does_not_use_shell():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                raise AssertionError("scripts/fix_linting_issues.py must not use shell=True")
