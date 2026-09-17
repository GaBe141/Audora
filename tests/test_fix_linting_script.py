"""Security tests for the linting maintenance script."""

import ast
from pathlib import Path

from scripts.fix_linting_issues import run_command


def test_linting_script_does_not_use_shell():
    source = Path("scripts/fix_linting_issues.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                assert keyword.value.value is not True


def test_run_command_invokes_argument_list(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run(cmd, check, capture_output, text):
        captured["cmd"] = cmd
        captured["check"] = check
        return None

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", _fake_run)
    assert run_command(["python", "-m", "ruff", "check"], "ruff") is True
    assert captured["cmd"] == ["python", "-m", "ruff", "check"]
    assert captured["check"] is True
