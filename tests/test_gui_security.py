"""Security tests for GUI auth configuration and safe filtering."""

import base64
import importlib
import sys
from pathlib import Path

import pandas as pd
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def app_module(monkeypatch):
    """Reload gui.app for isolated env-driven security config tests."""
    monkeypatch.delenv("AUDORA_GUI_DISABLE_AUTH", raising=False)
    monkeypatch.delenv("AUDORA_GUI_USERNAME", raising=False)
    monkeypatch.delenv("AUDORA_GUI_PASSWORD", raising=False)
    module = importlib.import_module("gui.app")
    module = importlib.reload(module)
    return module


def test_configure_security_uses_basic_auth_when_password_provided(app_module, monkeypatch):
    monkeypatch.setenv("AUDORA_GUI_USERNAME", "admin")
    monkeypatch.setenv("AUDORA_GUI_PASSWORD", "secret-pass")
    result = app_module.configure_security_from_env(app_module.app)
    assert result["mode"] == "basic_auth"
    assert result["username"] == "admin"


def test_basic_auth_checker_accepts_valid_credentials(app_module):
    checker = app_module._basic_auth_checker("admin", "secret-pass")
    token = base64.b64encode(b"admin:secret-pass").decode("ascii")
    with app_module.app.server.test_request_context(
        "/", headers={"Authorization": f"Basic {token}"}
    ):
        assert checker() is None


def test_basic_auth_checker_rejects_missing_header(app_module):
    checker = app_module._basic_auth_checker("admin", "secret-pass")
    with app_module.app.server.test_request_context("/"):
        response = checker()
        assert response is not None
        assert response.status_code == 401


def test_search_history_uses_literal_artist_filter(monkeypatch, app_module):
    class StubStore:
        def get_trending_tracks(self, **_kwargs):
            return pd.DataFrame(
                {
                    "track_name": ["A", "B"],
                    "artist": ["Taylor (Swift)", "Another Artist"],
                    "platform": ["tiktok", "youtube"],
                    "score": [95.5, 88.0],
                    "trend_date": ["2026-03-01", "2026-03-01"],
                }
            )

    monkeypatch.setattr(app_module, "_get_data_store", lambda: StubStore())
    # This would be interpreted as regex if regex=False were not set.
    rows = app_module.search_history(
        _n=1,
        platform="",
        min_score=0,
        days=30,
        artist_filter="Taylor (Swift)",
    )
    assert len(rows) == 1
    assert rows[0]["artist"] == "Taylor (Swift)"
