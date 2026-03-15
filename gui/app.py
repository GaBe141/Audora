"""
Audora prototyping GUI - Dash app.
Orchestrates main.py (discovery, demos, setup, validate) via subprocess and shows output.
"""

import subprocess
import sys
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, ctx, dcc, html

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG],
    suppress_callback_exceptions=True,
    title="Audora",
)

# Store for last run output and status
app.layout = dbc.Container(
    [
        dcc.Store(id="last-status", data="Idle"),
        dcc.Store(id="last-output", data=""),
        dbc.Row(
            [
                dbc.Col(
                    [
                        html.H4("Audora", className="mb-3"),
                        html.Hr(),
                        dbc.Button(
                            "Run single discovery",
                            id="btn-discovery",
                            color="primary",
                            className="w-100 mb-2",
                        ),
                        html.Label("Run demo:", className="mt-2 small text-muted"),
                        dbc.Select(
                            id="demo-select",
                            options=[
                                {"label": "Statistical", "value": "statistical"},
                                {"label": "Trending", "value": "trending"},
                                {"label": "Multi-source", "value": "multi_source"},
                                {"label": "Platform", "value": "platform"},
                                {"label": "All demos", "value": "all"},
                            ],
                            value="statistical",
                            className="mb-2",
                        ),
                        dbc.Button(
                            "Run demo",
                            id="btn-demo",
                            color="secondary",
                            className="w-100 mb-2",
                        ),
                        dbc.Button(
                            "Setup",
                            id="btn-setup",
                            color="info",
                            outline=True,
                            className="w-100 mb-2",
                        ),
                        dbc.Button(
                            "Validate",
                            id="btn-validate",
                            color="info",
                            outline=True,
                            className="w-100 mb-2",
                        ),
                    ],
                    width=3,
                    className="pt-4",
                ),
                dbc.Col(
                    [
                        html.H4("Output", className="mb-2"),
                        html.Div(
                            id="status-line",
                            children="Status: Idle",
                            className="mb-2 text-muted small",
                        ),
                        html.Div(
                            [
                                html.Pre(
                                    id="log-output",
                                    children="Run an action from the sidebar.",
                                    style={
                                        "backgroundColor": "#1a1a1a",
                                        "color": "#ccc",
                                        "padding": "1rem",
                                        "borderRadius": "4px",
                                        "maxHeight": "70vh",
                                        "overflow": "auto",
                                        "fontSize": "13px",
                                    },
                                ),
                            ],
                        ),
                    ],
                    width=9,
                    className="pt-4",
                ),
            ],
        ),
    ],
    fluid=True,
    className="p-4",
)


def _run_command(args: list[str]) -> tuple[str, str]:
    """Run a command in subprocess; return (status_str, combined_stdout_stderr)."""
    try:
        proc = subprocess.Popen(
            args,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out, _ = proc.communicate(timeout=300)
        exit_code = proc.returncode
        status = f"Done (exit {exit_code})"
        return status, out or "(no output)"
    except subprocess.TimeoutExpired:
        proc.kill()
        return "Done (timeout)", "(process timed out)"
    except Exception as e:
        return "Error", str(e)


@app.callback(
    Output("last-status", "data"),
    Output("last-output", "data"),
    Input("btn-discovery", "n_clicks"),
    Input("btn-demo", "n_clicks"),
    Input("btn-setup", "n_clicks"),
    Input("btn-validate", "n_clicks"),
    State("demo-select", "value"),
    prevent_initial_call=True,
)
def run_action(
    _discovery_clicks,
    _demo_clicks,
    _setup_clicks,
    _validate_clicks,
    demo_value,
):
    triggered = ctx.triggered_id
    if triggered == "btn-discovery":
        return _run_command([sys.executable, str(PROJECT_ROOT / "main.py"), "--mode", "single"])
    if triggered == "btn-demo":
        return _run_command([sys.executable, str(PROJECT_ROOT / "main.py"), "--demo", demo_value])
    if triggered == "btn-setup":
        return _run_command([sys.executable, str(PROJECT_ROOT / "main.py"), "--setup"])
    if triggered == "btn-validate":
        return _run_command([sys.executable, str(PROJECT_ROOT / "main.py"), "--validate"])
    raise dash.exceptions.PreventUpdate


@app.callback(
    Output("status-line", "children"),
    Output("log-output", "children"),
    Input("last-status", "data"),
    Input("last-output", "data"),
)
def update_display(status, output):
    status = status or "Idle"
    display_text = (output or "").strip() or "Run an action from the sidebar."
    return f"Status: {status}", display_text
