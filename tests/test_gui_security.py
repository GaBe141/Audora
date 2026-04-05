"""Security tests for sensitive GUI actions."""

from gui import app as gui_app


def test_is_admin_authorized_requires_both_tokens(monkeypatch):
    monkeypatch.delenv(gui_app.ADMIN_TOKEN_ENV, raising=False)
    assert gui_app._is_admin_authorized("admin-secret") is False

    monkeypatch.setenv(gui_app.ADMIN_TOKEN_ENV, "admin-secret")
    assert gui_app._is_admin_authorized(None) is False


def test_is_admin_authorized_validates_token_match(monkeypatch):
    monkeypatch.setenv(gui_app.ADMIN_TOKEN_ENV, "admin-secret")
    assert gui_app._is_admin_authorized("wrong-token") is False

    assert gui_app._is_admin_authorized("admin-secret") is True


def test_run_action_blocked_when_unauthorized(monkeypatch):
    monkeypatch.delenv(gui_app.ADMIN_TOKEN_ENV, raising=False)

    status, output = gui_app.run_action(1, None, None, None, "statistical", "any-token")
    assert status == "Unauthorized"
    assert "Blocked" in output

