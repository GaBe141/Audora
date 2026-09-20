"""Security tests for GUI command allowlisting and export limits."""

import pytest

from gui.app import (
    ALLOWED_DEMO_MODES,
    MAX_CSV_EXPORT_ROWS,
    _validated_command_args,
    _validated_demo_mode,
)


def test_demo_allowlist_matches_cli_choices():
    assert {
        "statistical",
        "trending",
        "multi_source",
        "platform",
        "all",
    } == ALLOWED_DEMO_MODES


def test_rejects_unknown_demo_mode():
    with pytest.raises(ValueError, match="Invalid demo mode"):
        _validated_demo_mode("statistical; rm -rf /")
    with pytest.raises(ValueError, match="Invalid demo mode"):
        _validated_demo_mode(["statistical"])


def test_accepts_allowlisted_demo_mode():
    assert _validated_demo_mode("trending") == "trending"


def test_rejects_nul_in_subprocess_args():
    with pytest.raises(ValueError, match="Invalid command arguments"):
        _validated_command_args(["python", "main.py\x00--setup"])


def test_rejects_non_string_subprocess_args():
    with pytest.raises(ValueError, match="Invalid command arguments"):
        _validated_command_args(["python", 123])  # type: ignore[list-item]


def test_csv_export_row_cap_is_finite():
    assert MAX_CSV_EXPORT_ROWS == 10_000
