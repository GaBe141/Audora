"""Security regression tests for the automated lint-fix helper."""

from scripts.fix_linting_issues import run_command


def test_run_command_uses_argument_list_without_shell(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs

    monkeypatch.setattr("scripts.fix_linting_issues.subprocess.run", fake_run)

    assert run_command(["python", "-m", "ruff", "check"], "safe command") is True
    assert captured["cmd"] == ["python", "-m", "ruff", "check"]
    assert "shell" not in captured["kwargs"]
