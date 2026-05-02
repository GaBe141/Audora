"""Security regression tests for the lint-fix helper script."""

import subprocess

from scripts import fix_linting_issues


def test_run_command_does_not_use_shell(monkeypatch):
    """Helper commands must run as argv lists to avoid shell injection."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(fix_linting_issues.subprocess, "run", fake_run)

    assert fix_linting_issues.run_command(["python", "-m", "ruff", "--version"], "check")

    assert calls == [
        (
            ["python", "-m", "ruff", "--version"],
            {"check": True, "capture_output": True, "text": True},
        )
    ]
