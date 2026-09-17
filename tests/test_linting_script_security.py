"""Security tests for the maintenance linting script."""

import subprocess
import sys
from unittest.mock import MagicMock

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell(monkeypatch):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run_command([sys.executable, "-c", "print(1)"], "safe command") is True
    assert captured["cmd"] == [sys.executable, "-c", "print(1)"]
    assert captured["kwargs"].get("shell") is not True
    assert captured["kwargs"].get("check") is True
