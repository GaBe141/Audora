"""Security tests for GUI command execution and export limits."""

from gui.app import (
    _ALLOWED_DEMO_MODES,
    _GUI_EXPORT_MAX_ROWS,
    _run_command,
    export_csv,
)


class TestGuiCommandHardening:
    """Subprocess helpers must reject malformed or unallowlisted input."""

    def test_demo_allowlist_is_closed(self):
        expected_modes = {
            "statistical",
            "trending",
            "multi_source",
            "platform",
            "all",
        }
        assert expected_modes == _ALLOWED_DEMO_MODES

    def test_run_command_rejects_non_list(self):
        status, output = _run_command("python -c 'print(1)'")  # type: ignore[arg-type]
        assert status == "Error"
        assert "Invalid command" in output

    def test_run_command_rejects_non_string_args(self):
        status, output = _run_command(["python", 1])  # type: ignore[list-item]
        assert status == "Error"
        assert "Invalid command arguments" in output

    def test_run_command_rejects_nul_bytes(self):
        status, output = _run_command(["python", "foo\x00bar"])
        assert status == "Error"
        assert "Invalid command arguments" in output


class TestGuiExportCap:
    """History CSV downloads must not stream unbounded tables."""

    def test_export_truncates_to_max_rows(self):
        table_data = [{"track_name": f"t{i}", "score": i} for i in range(_GUI_EXPORT_MAX_ROWS + 25)]
        payload = export_csv(1, table_data)
        content = payload["content"] if isinstance(payload, dict) else str(payload)
        assert content.count("\n") <= _GUI_EXPORT_MAX_ROWS + 1
