"""Security tests for the maintenance linting script."""

import inspect
import subprocess
import sys

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell(monkeypatch):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_command([sys.executable, "-c", "print(1)"], "safe") is True
    assert captured["cmd"] == [sys.executable, "-c", "print(1)"]
    assert captured["kwargs"].get("shell") is not True
    assert captured["kwargs"]["check"] is True


def test_script_source_has_no_shell_true():
    source = inspect.getsource(run_command)
    assert "shell=True" not in source
    assert "shell" not in inspect.signature(run_command).parameters
