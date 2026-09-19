"""Security tests for the lint auto-fix helper script."""

import ast
from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_lint_script_does_not_use_shell_true():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                assert keyword.value.value is not True


def test_run_command_passes_argument_list(monkeypatch):
    captured: dict = {}

    def fake_run(cmd, check=False, capture_output=False, text=False):
        captured["cmd"] = cmd
        captured["check"] = check
        captured["shell"] = False
        return None

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)
    assert run_command(["python", "-m", "ruff", "check"], "lint") is True
    assert captured["cmd"] == ["python", "-m", "ruff", "check"]
    assert captured["check"] is True
