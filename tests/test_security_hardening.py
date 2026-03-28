"""Security regression tests for critical hardening changes."""

import sys
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

# integrations.lastfm_integration imports integrations.config; ensure test isolation
if "integrations.config" not in sys.modules:
    _config_mock = MagicMock()
    _config_mock.get_config = lambda: MagicMock(get_lastfm_config=lambda: {"api_key": "test_key"})
    sys.modules["integrations.config"] = _config_mock

from integrations.lastfm_integration import BASE_URL, LastFmAPI
from scripts.fix_linting_issues import run_command


def test_lastfm_base_url_uses_https():
    """Last.fm client must not use plaintext HTTP."""
    assert BASE_URL.startswith("https://")


def test_lastfm_requests_use_https_endpoint():
    """All Last.fm requests should target the HTTPS API endpoint."""
    api = LastFmAPI(api_key="test_key")
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"artists": {"artist": []}}

    with patch.object(api.session, "get", return_value=mock_response) as mock_get:
        api.get_top_artists_global(limit=1)

    request_url = mock_get.call_args.args[0]
    assert request_url.startswith("https://")


def test_run_command_executes_without_shell():
    """run_command should avoid shell=True to prevent command injection."""
    with patch("scripts.fix_linting_issues.subprocess.run") as mock_run:
        mock_run.return_value = CompletedProcess(args=["python", "--version"], returncode=0)
        assert run_command("python --version", "Version check")

    kwargs = mock_run.call_args.kwargs
    assert kwargs.get("shell") is None
    assert kwargs["check"] is True
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True

    # Ensure command string was tokenized into argument list.
    assert mock_run.call_args.args[0] == ["python", "--version"]
