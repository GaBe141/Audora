"""Security tests for GUI hardening in gui/app.py source."""

from pathlib import Path


def test_gui_enforces_admin_token_gate_for_sensitive_actions():
    """Ensure sensitive callbacks stay protected by the admin token check."""
    source = (Path(__file__).resolve().parents[1] / "gui" / "app.py").read_text(encoding="utf-8")

    assert "ADMIN_TOKEN_ENV = \"AUDORA_GUI_ADMIN_TOKEN\"" in source
    assert "def _is_admin_authorized(" in source
    assert "State(\"admin-token\", \"value\")" in source
    assert "if not _is_admin_authorized(admin_token):" in source
    assert "return \"Unauthorized\"" in source

