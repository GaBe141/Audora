"""Security tests for the lint-fix helper script."""

import subprocess

from scripts.fix_linting_issues import run_command


def test_run_command_does_not_use_shell(monkeypatch):
    """Command arguments should be executed directly, not through a shell."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert run_command(["python", "-m", "ruff", "--version"], "checking ruff") is True
    assert captured["cmd"] == ["python", "-m", "ruff", "--version"]
    assert "shell" not in captured["kwargs"]
