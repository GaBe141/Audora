"""Security tests for scripts/fix_linting_issues command execution."""

from scripts import fix_linting_issues


def test_run_command_uses_argument_list_not_shell(monkeypatch):
    """Ensure run_command invokes subprocess without shell=True."""
    captured: dict[str, object] = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        class DummyCompletedProcess:
            returncode = 0

        return DummyCompletedProcess()

    monkeypatch.setattr(fix_linting_issues.subprocess, "run", fake_run)

    ok = fix_linting_issues.run_command("python -m black core/", "format")
    assert ok is True
    assert captured["args"] == ["python", "-m", "black", "core/"]
    assert captured["kwargs"]["check"] is True
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert "shell" not in captured["kwargs"]
