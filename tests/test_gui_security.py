"""Security checks for the Dash GUI callbacks."""

import sys
from types import SimpleNamespace

from gui.app import export_csv, save_settings


class TestGuiSecurity:
    """User-controlled callback values cannot widen the command or webhook surface."""

    def test_demo_callback_rejects_unknown_mode(self, monkeypatch):
        gui_module = sys.modules["gui.app"]
        monkeypatch.setattr(gui_module, "ctx", SimpleNamespace(triggered_id="btn-demo"))
        status, output = gui_module.run_action(None, 1, None, None, "statistical; touch /tmp/owned")
        assert status == "Error"
        assert output == "Unsupported demo mode"

    def test_csv_export_neutralizes_formulas(self):
        payload = export_csv(1, [{"track_name": "=1+1", "artist": "A"}])
        content = payload["content"]
        assert "'=1+1" in content

    def test_save_settings_rejects_loopback_webhook(self):
        message = save_settings(
            1,
            "https://127.0.0.1/hook",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        assert "private or restricted" in message
