"""Security tests for the Dash dashboard access gate."""

from gui.app import app


def test_dashboard_allows_loopback_without_admin_token(monkeypatch):
    monkeypatch.delenv("AUDORA_DASH_ADMIN_TOKEN", raising=False)

    with app.server.test_client() as client:
        response = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})

    assert response.status_code == 200


def test_dashboard_rejects_forwarded_non_loopback_without_token(monkeypatch):
    monkeypatch.delenv("AUDORA_DASH_ADMIN_TOKEN", raising=False)

    with app.server.test_client() as client:
        response = client.get(
            "/",
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

    assert response.status_code == 401


def test_dashboard_requires_matching_admin_token(monkeypatch):
    monkeypatch.setenv("AUDORA_DASH_ADMIN_TOKEN", "expected-token")

    with app.server.test_client() as client:
        rejected = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        accepted = client.get(
            "/",
            environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
            headers={"Authorization": "Bearer expected-token"},
        )

    assert rejected.status_code == 401
    assert accepted.status_code == 200
