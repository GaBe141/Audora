"""Security checks for the lint auto-fix maintenance script."""

import ast
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "fix_linting_issues.py"


def test_lint_script_does_not_use_shell_true():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    assert keyword.value.value is not True


def test_lint_script_uses_argument_lists():
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
    assert "list[str]" in source
