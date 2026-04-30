"""Security tests for GUI admin actions."""

import importlib
import pytest

gui_app = importlib.import_module("gui.app")


def test_rejects_remote_admin_actions_without_token(monkeypatch):
    monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)

    with gui_app.app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.10"}):
        with pytest.raises(PermissionError, match="localhost"):
            gui_app._require_admin_action_allowed()


def test_allows_loopback_admin_actions_without_token(monkeypatch):
    monkeypatch.delenv("AUDORA_GUI_ADMIN_TOKEN", raising=False)

    with gui_app.app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        gui_app._require_admin_action_allowed()


def test_allows_remote_admin_actions_with_configured_token(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "test-token")

    headers = {"X-Audora-Admin-Token": "test-token"}
    with gui_app.app.server.test_request_context(
        "/", headers=headers, environ_base={"REMOTE_ADDR": "203.0.113.10"}
    ):
        gui_app._require_admin_action_allowed()


def test_rejects_remote_admin_actions_with_wrong_token(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ADMIN_TOKEN", "test-token")

    headers = {"X-Audora-Admin-Token": "wrong-token"}
    with gui_app.app.server.test_request_context(
        "/", headers=headers, environ_base={"REMOTE_ADDR": "203.0.113.10"}
    ):
        with pytest.raises(PermissionError, match="X-Audora-Admin-Token"):
            gui_app._require_admin_action_allowed()


def test_run_command_returns_error_when_admin_action_rejected(monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_ENABLE_ADMIN_ACTIONS", "0")

    with gui_app.app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        status, output = gui_app._run_command(["python", "--version"])

    assert status == "Error"
    assert "disabled" in output
