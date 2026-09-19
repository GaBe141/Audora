"""Security tests for the lint auto-fix helper."""

import inspect
import subprocess
import sys

from scripts import fix_linting_issues
from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_command([sys.executable, "-m", "black", "--help"], "test") is True
    assert captured["cmd"] == [sys.executable, "-m", "black", "--help"]
    assert captured["kwargs"].get("shell") in (None, False)


def test_run_command_rejects_string_command():
    assert run_command("echo hi", "should fail type check") is False  # type: ignore[arg-type]


def test_source_has_no_shell_true():
    source = inspect.getsource(fix_linting_issues)
    assert "shell=True" not in source
    assert "shell=True" not in inspect.getsource(fix_linting_issues.run_command)
