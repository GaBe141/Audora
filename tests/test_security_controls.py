"""Tests for redirect URI and CSV formula hardening."""

import pytest

from core.config import SecureConfig
from core.utils import neutralize_csv_cell


class TestSpotifyRedirectUri:
    """Redirect URIs must be an exact loopback host."""

    def test_rejects_lookalike_localhost_host(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "abc")
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "def")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://localhost.evil.com/callback")
        config = SecureConfig(env_file=str(tmp_path / "missing.env"))
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            config.get_spotify_config()

    def test_rejects_decimal_suffix_on_loopback_ip(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "abc")
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "def")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1.evil.com/callback")
        config = SecureConfig(env_file=str(tmp_path / "missing.env"))
        with pytest.raises(ValueError, match="Invalid redirect URI"):
            config.get_spotify_config()

    def test_accepts_exact_loopback_ip(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SPOTIFY_CLIENT_ID", "abc")
        monkeypatch.setenv("SPOTIFY_CLIENT_SECRET", "def")
        monkeypatch.setenv("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")
        config = SecureConfig(env_file=str(tmp_path / "missing.env"))
        assert config.get_spotify_config()["redirect_uri"] == "http://127.0.0.1:8888/callback"


class TestCsvNeutralization:
    """Spreadsheet formula prefixes are neutralized, including leading whitespace."""

    def test_prefixes_formula_text(self):
        assert neutralize_csv_cell("=1+1") == "'=1+1"
        assert neutralize_csv_cell(" =1+1") == "' =1+1"
        assert neutralize_csv_cell("\t@cmd") == "'\t@cmd"
        assert neutralize_csv_cell("Taylor") == "Taylor"
        assert neutralize_csv_cell(3) == 3
