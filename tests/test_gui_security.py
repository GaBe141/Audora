"""Security checks for dashboard actions that accept user input."""

import sys

import gui  # noqa: F401

# gui/__init__.py rebinds the package attribute `app` to the Dash instance.
gui_app = sys.modules["gui.app"]


class _Ctx:
    def __init__(self, triggered_id: str) -> None:
        self.triggered_id = triggered_id


def test_unsupported_demo_mode(monkeypatch):
    monkeypatch.setattr(gui_app, "ctx", _Ctx("btn-demo"))
    status, output = gui_app.run_action(None, 1, None, None, "not-a-real-demo")
    assert status == "Error"
    assert output == "Unsupported demo mode"


def test_save_settings_rejects_loopback_webhook():
    result = gui_app.save_settings(
        1,
        None,
        None,
        "https://127.0.0.1/hook",
        None,
        None,
        None,
        None,
    )
    assert "private or restricted" in result


def test_export_csv_neutralizes_formula_cells():
    payload = gui_app.export_csv(1, [{"track": "=1+1"}])
    content = payload["content"]
    if payload.get("base64"):
        import base64

        content = base64.b64decode(content).decode("utf-8")
    assert "'=1+1" in content
