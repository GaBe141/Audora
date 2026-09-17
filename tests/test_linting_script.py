"""Security tests for the maintenance linting script."""

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell(monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

        class Result:
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)
    assert run_command(["ruff", "check"], "noop") is True
    assert captured["cmd"] == ["ruff", "check"]
    assert captured["kwargs"].get("shell", False) is False
