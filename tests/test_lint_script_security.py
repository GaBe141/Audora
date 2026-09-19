"""Security tests for the lint auto-fix maintenance script."""

import ast
from pathlib import Path


def test_lint_script_does_not_use_shell_true():
    source_path = Path("scripts/fix_linting_issues.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                raise AssertionError("scripts/fix_linting_issues.py must not use shell=True")
