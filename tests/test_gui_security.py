"""Security tests for sensitive Dash GUI callbacks."""

import importlib

gui_app = importlib.import_module("gui.app")


class TestGuiLocalRequestGuard:
    """Validate localhost gating for GUI control-plane callbacks."""

    def test_allows_loopback_request(self):
        with gui_app.app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            assert gui_app._require_local_request() == (True, None)

    def test_blocks_remote_request(self):
        with gui_app.app.server.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.10"}):
            allowed, error = gui_app._require_local_request()

        assert allowed is False
        assert error == "Sensitive GUI actions are only available from localhost."

    def test_ignores_spoofed_forwarded_for_header(self):
        with gui_app.app.server.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "203.0.113.10"},
            headers={"X-Forwarded-For": "127.0.0.1"},
        ):
            allowed, _ = gui_app._require_local_request()

        assert allowed is False
