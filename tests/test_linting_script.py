"""Security tests for the maintenance linting script."""

import subprocess
from unittest.mock import patch

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_not_shell():
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with patch("scripts.fix_linting_issues.subprocess.run", side_effect=fake_run):
        assert run_command(["echo", "ok"], "safe command") is True

    assert captured["cmd"] == ["echo", "ok"]
    assert captured["kwargs"].get("shell") is not True


def test_run_command_rejects_string_payload():
    with patch("scripts.fix_linting_issues.subprocess.run") as fake_run:
        assert run_command("echo pwned", "unsafe") is False  # type: ignore[arg-type]
    fake_run.assert_not_called()
