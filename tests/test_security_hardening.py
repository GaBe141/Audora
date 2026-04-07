"""Security regression tests for recently hardened code paths."""

import subprocess

import pytest

from scripts.fix_linting_issues import run_command


class TestFixLintingIssuesCommandExecution:
    """Ensure command execution does not use shell interpolation."""

    def test_run_command_uses_argument_list_without_shell(self, monkeypatch):
        recorded: dict[str, object] = {}

        def fake_run(*args, **kwargs):
            recorded["args"] = args
            recorded["kwargs"] = kwargs

            class DummyResult:
                returncode = 0

            return DummyResult()

        monkeypatch.setattr(subprocess, "run", fake_run)

        assert run_command(["echo", "ok"], "test command")
        assert recorded["args"][0] == ["echo", "ok"]
        assert "shell" not in recorded["kwargs"]

    def test_run_command_returns_false_on_called_process_error(self, monkeypatch):
        def fake_run(*_args, **_kwargs):
            raise subprocess.CalledProcessError(returncode=1, cmd=["x"], stderr="boom")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert run_command(["echo", "ok"], "test command") is False


class TestDataStoreExportTableValidation:
    """Validate strict export table handling to prevent injection."""

    def test_export_to_csv_rejects_invalid_table(self, data_store, tmp_path):
        output = tmp_path / "out.csv"
        with pytest.raises(ValueError, match="Invalid table name"):
            data_store.export_to_csv("trends; DROP TABLE trends; --", str(output))

