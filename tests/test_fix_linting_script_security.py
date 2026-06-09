"""Security regression tests for the lint-fix helper script."""

import subprocess

from scripts import fix_linting_issues


def test_run_command_does_not_use_shell(monkeypatch):
    """Commands must be passed as argument vectors, never through a shell."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(fix_linting_issues.subprocess, "run", fake_run)

    assert fix_linting_issues.run_command(["python3", "--version"], "check interpreter")

    assert calls == [
        (
            ["python3", "--version"],
            {"check": True, "capture_output": True, "text": True},
        )
    ]
    assert "shell" not in calls[0][1]
