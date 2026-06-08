"""
Audora prototyping GUI - Dash app.
Orchestrates main.py (discovery, demos, setup, validate) via subprocess and shows output.
Includes live trend dashboard, history search, notification settings, and accuracy tracking.
"""

import subprocess
import sys
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import Input, Output, State, ctx, dash_table, dcc, html

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG],
    suppress_callback_exceptions=True,
    title="Audora",
)

# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def _stat_card(card_id: str, label: str) -> dbc.Card:
    return dbc.Card(
        dbc.CardBody([
            html.P(label, className="text-muted small mb-1"),
            html.H4("—", id=card_id, className="mb-0"),
        ]),
        className="text-center mb-3",
    )


# ---------------------------------------------------------------------------
# Tab: Dashboard
# ---------------------------------------------------------------------------

_dashboard_tab = dbc.Tab(
    label="Dashboard",
    tab_id="tab-dashboard",
    children=[
        dcc.Interval(id="auto-refresh", interval=30_000, n_intervals=0),
        dbc.Row([
            dbc.Col(_stat_card("stat-tracks", "Unique Tracks (7d)"), width=4),
            dbc.Col(_stat_card("stat-score", "Avg Viral Score"), width=4),
            dbc.Col(_stat_card("stat-platform", "Most Active Platform"), width=4),
        ], className="mt-3"),
        dbc.Row([
            dbc.Col(dcc.Graph(id="trend-bar", style={"height": "320px"}), width=8),
            dbc.Col(dcc.Graph(id="platform-pie", style={"height": "320px"}), width=4),
        ]),
        html.Hr(),
        dbc.Button(
            "Show / Hide Log",
            id="btn-toggle-log",
            color="secondary",
            size="sm",
            outline=True,
            className="mb-2",
        ),
        dbc.Collapse(
            id="log-collapse",
            is_open=False,
            children=[
                html.Div(
                    id="status-line",
                    children="Status: Idle",
                    className="mb-1 text-muted small",
                ),
                html.Pre(
                    id="log-output",
                    children="Run an action from the sidebar.",
                    style={
                        "backgroundColor": "#1a1a1a",
                        "color": "#ccc",
                        "padding": "1rem",
                        "borderRadius": "4px",
                        "maxHeight": "40vh",
                        "overflow": "auto",
                        "fontSize": "13px",
                    },
                ),
            ],
        ),
    ],
)

# ---------------------------------------------------------------------------
# Tab: History
# ---------------------------------------------------------------------------

_history_tab = dbc.Tab(
    label="History",
    tab_id="tab-history",
    children=[
        dbc.Row([
            dbc.Col([
                html.Label("Platform", className="small text-muted"),
                dbc.Select(
                    id="hist-platform",
                    options=[
                        {"label": "All", "value": ""},
                        {"label": "TikTok", "value": "tiktok"},
                        {"label": "YouTube", "value": "youtube"},
                        {"label": "Twitter", "value": "twitter"},
                        {"label": "Last.fm", "value": "lastfm"},
                    ],
                    value="",
                    className="mb-2",
                ),
            ], width=2),
            dbc.Col([
                html.Label("Min Score", className="small text-muted"),
                dcc.Slider(
                    id="hist-min-score",
                    min=0, max=100, step=5, value=0,
                    marks={0: "0", 50: "50", 100: "100"},
                    className="mb-2",
                ),
            ], width=3),
            dbc.Col([
                html.Label("Days Back", className="small text-muted"),
                dbc.Input(
                    id="hist-days",
                    type="number",
                    value=30,
                    min=1,
                    max=365,
                    className="mb-2",
                ),
            ], width=2),
            dbc.Col([
                html.Label("Artist search", className="small text-muted"),
                dbc.Input(id="hist-artist", placeholder="e.g. Taylor Swift", className="mb-2"),
            ], width=3),
            dbc.Col([
                html.Br(),
                dbc.Button("Search", id="btn-hist-search", color="primary", className="w-100 mb-2"),
            ], width=2),
        ], className="mt-3 align-items-end"),
        dbc.Button(
            "Export CSV",
            id="btn-hist-export",
            color="success",
            size="sm",
            outline=True,
            className="mb-2",
        ),
        dcc.Download(id="hist-download"),
        dash_table.DataTable(
            id="history-table",
            columns=[
                {"name": "Track", "id": "track_name"},
                {"name": "Artist", "id": "artist"},
                {"name": "Platform", "id": "platform"},
                {"name": "Score", "id": "score"},
                {"name": "Date", "id": "trend_date"},
            ],
            data=[],
            page_size=20,
            style_table={"overflowX": "auto"},
            style_cell={"backgroundColor": "#1a1a1a", "color": "#ccc", "fontSize": "13px"},
            style_header={"backgroundColor": "#2a2a2a", "fontWeight": "bold"},
        ),
    ],
)

# ---------------------------------------------------------------------------
# Tab: Settings (notification channels)
# ---------------------------------------------------------------------------

def _channel_row(label: str, input_id: str, channel_key: str) -> dbc.Row:
    return dbc.Row([
        dbc.Col(html.Label(label, className="small text-muted pt-2"), width=2),
        dbc.Col(dbc.Input(id=input_id, placeholder="https://...", type="url"), width=7),
        dbc.Col(
            dbc.Button(
                "Test",
                id=f"btn-test-{channel_key}",
                color="info",
                size="sm",
                outline=True,
            ),
            width=2,
        ),
        dbc.Col(html.Span("", id=f"test-status-{channel_key}", className="small"), width=1),
    ], className="mb-2 align-items-center")


_settings_tab = dbc.Tab(
    label="Settings",
    tab_id="tab-settings",
    children=[
        html.H5("Notification Channels", className="mt-3 mb-3"),
        _channel_row("Slack Webhook", "input-slack-url", "slack"),
        _channel_row("Discord Webhook", "input-discord-url", "discord"),
        _channel_row("Custom Webhook", "input-webhook-url", "webhook"),
        html.Hr(),
        html.H6("Email (SMTP)", className="mb-2"),
        dbc.Row([
            dbc.Col(dbc.Input(id="input-smtp-host", placeholder="smtp.example.com"), width=4),
            dbc.Col(dbc.Input(id="input-smtp-port", placeholder="587", type="number", value=587), width=2),
            dbc.Col(dbc.Input(id="input-smtp-user", placeholder="username"), width=3),
            dbc.Col(dbc.Input(id="input-smtp-pass", placeholder="password", type="password"), width=3),
        ], className="mb-2"),
        dbc.Row([
            dbc.Col(
                dbc.Button("Save Settings", id="btn-save-settings", color="primary"),
                width="auto",
            ),
            dbc.Col(html.Span("", id="settings-save-status", className="small pt-2"), width="auto"),
        ], className="mt-2 align-items-center"),
    ],
)

# ---------------------------------------------------------------------------
# Tab: Accuracy
# ---------------------------------------------------------------------------

_accuracy_tab = dbc.Tab(
    label="Accuracy",
    tab_id="tab-accuracy",
    children=[
        dbc.Row([
            dbc.Col(_stat_card("acc-total", "Predictions Evaluated"), width=3),
            dbc.Col(_stat_card("acc-pct", "Mean Accuracy"), width=3),
            dbc.Col(_stat_card("acc-mae", "MAE"), width=3),
            dbc.Col(_stat_card("acc-rmse", "RMSE"), width=3),
        ], className="mt-3"),
        dbc.Button(
            "Evaluate Now",
            id="btn-evaluate",
            color="primary",
            className="mb-3",
        ),
        dbc.Row([
            dbc.Col(dcc.Graph(id="accuracy-by-platform", style={"height": "300px"}), width=6),
            dbc.Col(
                dash_table.DataTable(
                    id="predictions-table",
                    columns=[
                        {"name": "Track", "id": "track_name"},
                        {"name": "Artist", "id": "artist"},
                        {"name": "Predicted", "id": "predicted_peak_score"},
                        {"name": "Actual", "id": "actual_peak_score"},
                        {"name": "Accuracy", "id": "accuracy_score"},
                        {"name": "Status", "id": "status"},
                    ],
                    data=[],
                    page_size=10,
                    style_table={"overflowX": "auto"},
                    style_cell={"backgroundColor": "#1a1a1a", "color": "#ccc", "fontSize": "13px"},
                    style_header={"backgroundColor": "#2a2a2a", "fontWeight": "bold"},
                ),
                width=6,
            ),
        ]),
    ],
)

# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------

app.layout = dbc.Container(
    [
        dcc.Store(id="last-status", data="Idle"),
        dcc.Store(id="last-output", data=""),
        dbc.Row([
            # Sidebar
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
                width=2,
                className="pt-4",
            ),
            # Main content
            dbc.Col(
                dbc.Tabs(
                    id="main-tabs",
                    active_tab="tab-dashboard",
                    children=[_dashboard_tab, _history_tab, _settings_tab, _accuracy_tab],
                ),
                width=10,
                className="pt-4",
            ),
        ]),
    ],
    fluid=True,
    className="p-4",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _get_data_store():
    """Return an EnhancedMusicDataStore pointed at the default DB path."""
    from core.data_store import EnhancedMusicDataStore
    db_path = PROJECT_ROOT / "data" / "enhanced_music_trends.db"
    return EnhancedMusicDataStore(str(db_path))


# ---------------------------------------------------------------------------
# Callbacks — sidebar actions
# ---------------------------------------------------------------------------

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
def update_log_display(status, output):
    status = status or "Idle"
    display_text = (output or "").strip() or "Run an action from the sidebar."
    return f"Status: {status}", display_text


@app.callback(
    Output("log-collapse", "is_open"),
    Input("btn-toggle-log", "n_clicks"),
    State("log-collapse", "is_open"),
    prevent_initial_call=True,
)
def toggle_log(n_clicks, is_open):
    return not is_open


# ---------------------------------------------------------------------------
# Callbacks — dashboard charts (Phase 2)
# ---------------------------------------------------------------------------

@app.callback(
    Output("stat-tracks", "children"),
    Output("stat-score", "children"),
    Output("stat-platform", "children"),
    Output("trend-bar", "figure"),
    Output("platform-pie", "figure"),
    Input("auto-refresh", "n_intervals"),
    Input("last-status", "data"),
)
def update_dashboard(_n, _status):
    try:
        store = _get_data_store()
        summary = store.get_trending_summary_cached(days=7)
    except Exception:
        empty_fig = go.Figure()
        empty_fig.update_layout(
            paper_bgcolor="#1a1a1a",
            plot_bgcolor="#1a1a1a",
            font_color="#ccc",
        )
        return "—", "—", "—", empty_fig, empty_fig

    stats = summary.get("stats", {})
    unique_tracks = int(stats.get("unique_tracks") or 0)
    avg_score = stats.get("avg_score")
    avg_score_str = f"{avg_score:.1f}" if avg_score is not None else "—"
    top_tracks = summary.get("top_tracks", [])

    # Determine most active platform from top tracks
    platform_counts: dict[str, int] = {}
    for t in top_tracks:
        p = t.get("platform", "unknown")
        platform_counts[p] = platform_counts.get(p, 0) + 1
    top_platform = max(platform_counts, key=lambda k: platform_counts[k]) if platform_counts else "—"

    # --- Trend bar chart ---
    names = [f"{t.get('track_name', '')} — {t.get('artist', '')}" for t in top_tracks]
    scores = [t.get("score", 0) for t in top_tracks]
    bar_fig = go.Figure(
        go.Bar(
            x=scores,
            y=names,
            orientation="h",
            marker_color="#7B68EE",
        )
    )
    bar_fig.update_layout(
        title="Top 10 Trending Tracks",
        paper_bgcolor="#1a1a1a",
        plot_bgcolor="#1a1a1a",
        font_color="#ccc",
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        xaxis_title="Score",
        yaxis={"autorange": "reversed"},
    )

    # --- Platform pie chart ---
    pie_fig = go.Figure(
        go.Pie(
            labels=list(platform_counts.keys()),
            values=list(platform_counts.values()),
            hole=0.4,
        )
    )
    pie_fig.update_layout(
        title="Platform Share",
        paper_bgcolor="#1a1a1a",
        plot_bgcolor="#1a1a1a",
        font_color="#ccc",
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        showlegend=True,
    )

    return str(unique_tracks), avg_score_str, top_platform, bar_fig, pie_fig


# ---------------------------------------------------------------------------
# Callbacks — history search (Phase 3)
# ---------------------------------------------------------------------------

@app.callback(
    Output("history-table", "data"),
    Input("btn-hist-search", "n_clicks"),
    State("hist-platform", "value"),
    State("hist-min-score", "value"),
    State("hist-days", "value"),
    State("hist-artist", "value"),
    prevent_initial_call=True,
)
def search_history(_n, platform, min_score, days, artist_filter):
    try:
        store = _get_data_store()
        df = store.get_trending_tracks(
            platform=platform or None,
            days=int(days or 30),
            min_score=float(min_score or 0),
            limit=200,
        )
    except Exception:
        return []

    if df.empty:
        return []

    # Drop the metadata column (dict) before sending to DataTable
    for drop_col in ("metadata", "avg_velocity", "data_points"):
        if drop_col in df.columns:
            df = df.drop(columns=[drop_col])

    # Optional artist filter (client-side simple substring)
    if artist_filter:
        mask = df["artist"].str.contains(artist_filter, case=False, na=False)
        df = df[mask]

    # Round score
    if "score" in df.columns:
        df["score"] = df["score"].round(1)

    return df.to_dict("records")


@app.callback(
    Output("hist-download", "data"),
    Input("btn-hist-export", "n_clicks"),
    State("history-table", "data"),
    prevent_initial_call=True,
)
def export_csv(_n, table_data):
    if not table_data:
        raise dash.exceptions.PreventUpdate
    import io

    import pandas as pd
    df = pd.DataFrame(table_data)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return dcc.send_string(buf.getvalue(), "audora_trends.csv")


# ---------------------------------------------------------------------------
# Callbacks — notification settings (Phase 4)
# ---------------------------------------------------------------------------

@app.callback(
    Output("settings-save-status", "children"),
    Input("btn-save-settings", "n_clicks"),
    State("input-slack-url", "value"),
    State("input-discord-url", "value"),
    State("input-webhook-url", "value"),
    State("input-smtp-host", "value"),
    State("input-smtp-port", "value"),
    State("input-smtp-user", "value"),
    State("input-smtp-pass", "value"),
    prevent_initial_call=True,
)
def save_settings(_n, slack_url, discord_url, webhook_url, smtp_host, smtp_port, smtp_user, smtp_pass):
    try:
        from core.notification_service import EnhancedNotificationService
        svc = EnhancedNotificationService()
        if slack_url:
            svc._validate_webhook_url(
                slack_url,
                allow_private=False,
                allowed_hosts={"hooks.slack.com", "hooks.slack-gov.com"},
            )
            svc.config["slack"]["webhook_url"] = slack_url
        if discord_url:
            svc._validate_webhook_url(
                discord_url,
                allow_private=False,
                allowed_hosts={"discord.com", "discordapp.com"},
            )
            svc.config["discord"]["webhook_url"] = discord_url
        if webhook_url:
            svc._validate_webhook_url(
                webhook_url,
                allow_private=svc._allow_private_webhooks(),
            )
            svc.config["webhook"]["url"] = webhook_url
        if smtp_host:
            svc.config["email"]["smtp_server"] = smtp_host
        if smtp_port:
            svc.config["email"]["port"] = int(smtp_port)
        if smtp_user:
            svc.config["email"]["username"] = smtp_user
        if smtp_pass:
            svc.config["email"]["password"] = smtp_pass
        svc.save_config()
        return "Saved"
    except Exception as e:
        return f"Error: {e}"


def _test_channel_callback(channel_key: str, url_input_id: str, channel_enum_name: str):
    """Register a test-channel callback for the given channel."""

    @app.callback(
        Output(f"test-status-{channel_key}", "children"),
        Input(f"btn-test-{channel_key}", "n_clicks"),
        State(url_input_id, "value"),
        prevent_initial_call=True,
    )
    def _cb(_n, url):
        if not url:
            return "No URL"
        try:
            import asyncio

            from core.notification_service import (
                EnhancedNotificationService,
                NotificationChannel,
                NotificationMessage,
                NotificationPriority,
            )
            svc = EnhancedNotificationService()
            svc.config[channel_key]["webhook_url" if channel_key != "webhook" else "url"] = url
            channel = getattr(NotificationChannel, channel_enum_name)
            msg = NotificationMessage(
                title="Audora test notification",
                content="This is a test message from Audora.",
                priority=NotificationPriority.LOW,
                channels=[channel],
            )
            asyncio.run(svc.send_notification(msg))
            return "OK"
        except Exception as e:
            return f"Fail: {e}"


_test_channel_callback("slack", "input-slack-url", "SLACK")
_test_channel_callback("discord", "input-discord-url", "DISCORD")
_test_channel_callback("webhook", "input-webhook-url", "WEBHOOK")


# ---------------------------------------------------------------------------
# Callbacks — accuracy tracking (Phase 5)
# ---------------------------------------------------------------------------

@app.callback(
    Output("acc-total", "children"),
    Output("acc-pct", "children"),
    Output("acc-mae", "children"),
    Output("acc-rmse", "children"),
    Output("accuracy-by-platform", "figure"),
    Output("predictions-table", "data"),
    Input("btn-evaluate", "n_clicks"),
    prevent_initial_call=True,
)
def evaluate_accuracy(_n):
    try:
        store = _get_data_store()
        metrics = store.evaluate_prediction_accuracy(days_back=30)
        pred_df = store.get_viral_predictions(confidence_threshold=0.0, status=None, days=30, limit=50)
    except Exception as e:
        empty_fig = go.Figure()
        empty_fig.update_layout(paper_bgcolor="#1a1a1a", plot_bgcolor="#1a1a1a", font_color="#ccc")
        return f"Error: {e}", "—", "—", "—", empty_fig, []

    total = metrics.get("total_evaluated", 0)
    mean_acc = metrics.get("mean_accuracy", 0)
    mae = metrics.get("mae", 0)
    rmse = metrics.get("rmse", 0)

    acc_by_platform = metrics.get("accuracy_by_platform", {})
    if acc_by_platform:
        bar_fig = go.Figure(
            go.Bar(
                x=list(acc_by_platform.keys()),
                y=[v * 100 for v in acc_by_platform.values()],
                marker_color="#44FF88",
            )
        )
        bar_fig.update_layout(
            title="Accuracy % by Platform",
            paper_bgcolor="#1a1a1a",
            plot_bgcolor="#1a1a1a",
            font_color="#ccc",
            yaxis_range=[0, 100],
            margin={"l": 20, "r": 20, "t": 40, "b": 20},
        )
    else:
        bar_fig = go.Figure()
        bar_fig.update_layout(
            title="No data yet",
            paper_bgcolor="#1a1a1a",
            plot_bgcolor="#1a1a1a",
            font_color="#ccc",
        )

    if not pred_df.empty:
        for drop_col in ("prediction_features",):
            if drop_col in pred_df.columns:
                pred_df = pred_df.drop(columns=[drop_col])
        for col in ("predicted_peak_score", "actual_peak_score", "accuracy_score", "confidence"):
            if col in pred_df.columns:
                pred_df[col] = pred_df[col].round(2)
        table_data = pred_df.to_dict("records")
    else:
        table_data = []

    return (
        str(total),
        f"{mean_acc * 100:.1f}%",
        str(mae),
        str(rmse),
        bar_fig,
        table_data,
    )
