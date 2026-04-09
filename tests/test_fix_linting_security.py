"""Security regression tests for scripts/fix_linting_issues.py."""

import scripts.fix_linting_issues as fixer


class TestFixLintingSecurity:
    """Ensure command execution avoids shell injection vectors."""

    def test_run_command_invokes_subprocess_without_shell(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return None

        monkeypatch.setattr(fixer.subprocess, "run", fake_run)

        result = fixer.run_command(["echo", "hello"], "test command")
        assert result is True

        assert captured["args"] == (["echo", "hello"],)
        kwargs = captured["kwargs"]
        assert kwargs["check"] is True
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        # Critical: run_command must never use shell=True.
        assert kwargs.get("shell", False) is False
