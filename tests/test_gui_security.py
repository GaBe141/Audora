"""Security tests for the Dash admin dashboard guard."""

import base64

from gui import app as gui_app


def _auth_header(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_dashboard_denies_remote_clients_without_credentials(monkeypatch):
    monkeypatch.setattr(gui_app, "GUI_USERNAME", "")
    monkeypatch.setattr(gui_app, "GUI_PASSWORD", "")
    monkeypatch.delenv("AUDORA_GUI_ALLOW_REMOTE", raising=False)

    client = gui_app.app.server.test_client()
    response = client.get("/", environ_base={"REMOTE_ADDR": "203.0.113.10"})

    assert response.status_code == 403


def test_dashboard_allows_loopback_clients_without_credentials(monkeypatch):
    monkeypatch.setattr(gui_app, "GUI_USERNAME", "")
    monkeypatch.setattr(gui_app, "GUI_PASSWORD", "")

    client = gui_app.app.server.test_client()
    response = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})

    assert response.status_code == 200


def test_dashboard_requires_basic_auth_when_credentials_are_configured(monkeypatch):
    monkeypatch.setattr(gui_app, "GUI_USERNAME", "admin")
    monkeypatch.setattr(gui_app, "GUI_PASSWORD", "secret")

    client = gui_app.app.server.test_client()
    unauthenticated = client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})
    authenticated = client.get(
        "/",
        headers=_auth_header("admin", "secret"),
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
    )

    assert unauthenticated.status_code == 401
    assert authenticated.status_code == 200


def test_dashboard_rejects_mutating_requests_without_same_origin(monkeypatch):
    monkeypatch.setattr(gui_app, "GUI_USERNAME", "admin")
    monkeypatch.setattr(gui_app, "GUI_PASSWORD", "secret")

    client = gui_app.app.server.test_client()
    response = client.post(
        "/_dash-update-component",
        headers=_auth_header("admin", "secret"),
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 403


def test_dashboard_accepts_mutating_requests_with_same_origin(monkeypatch):
    monkeypatch.setattr(gui_app, "GUI_USERNAME", "admin")
    monkeypatch.setattr(gui_app, "GUI_PASSWORD", "secret")

    client = gui_app.app.server.test_client()
    response = client.post(
        "/_dash-update-component",
        headers={
            **_auth_header("admin", "secret"),
            "Origin": "http://localhost",
            "Content-Type": "application/json",
        },
        json={},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code != 403
