"""Security tests for GUI subprocess and webhook configuration."""

import pytest

from gui.app import ALLOWED_DEMO_MODES, _run_command, _validated_demo_value


def test_demo_allowlist_matches_cli_choices():
    expected = frozenset({"statistical", "trending", "multi_source", "platform", "all"})
    assert expected == ALLOWED_DEMO_MODES


def test_run_command_rejects_non_string_args():
    status, output = _run_command([123, "main.py"])  # type: ignore[list-item]
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_run_command_rejects_nul_bytes():
    status, output = _run_command(["python", "main.py\x00--setup"])
    assert status == "Error"
    assert "Invalid command arguments" in output


def test_validated_demo_value_rejects_unknown_mode():
    with pytest.raises(ValueError, match="Invalid demo mode"):
        _validated_demo_value("not-a-demo; rm -rf /")
    assert _validated_demo_value("statistical") == "statistical"
