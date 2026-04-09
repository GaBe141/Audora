"""Security-focused tests for scripts.fix_linting_issues."""

import subprocess

from scripts.fix_linting_issues import run_command


def test_run_command_uses_safe_subprocess_invocation(monkeypatch):
    """Ensure shell execution is not used for command dispatch."""
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert run_command(["python", "--version"], "Check Python version")
    assert isinstance(captured["cmd"], list)
    assert "shell" not in captured["kwargs"]
    assert captured["kwargs"]["check"] is True


def test_run_command_returns_false_on_called_process_error(monkeypatch):
    """Failed subprocess executions should return False."""

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert not run_command(["python", "--bad-flag"], "Force a command failure")
