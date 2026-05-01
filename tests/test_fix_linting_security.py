"""Security tests for the automated lint-fix helper."""

import subprocess
import sys

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell(monkeypatch):
    """Commands should execute without shell parsing to prevent injection."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert run_command([sys.executable, "-m", "ruff", "--version"], "Check ruff")

    assert calls == [
        (
            [sys.executable, "-m", "ruff", "--version"],
            {"check": True, "capture_output": True, "text": True},
        )
    ]
