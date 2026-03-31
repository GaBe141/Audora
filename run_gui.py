#!/usr/bin/env python3
"""
Audora prototyping GUI - entry point.
Starts the Dash server at http://127.0.0.1:8050
"""

import ipaddress
import os
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.app import app  # noqa: E402


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback_host(host: str) -> bool:
    normalized = (host or "").strip().lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_gui_security_policy(host: str) -> None:
    """Enforce secure defaults when binding the GUI server."""
    if _is_loopback_host(host):
        return

    if not _env_flag("AUDORA_GUI_ALLOW_REMOTE", default=False):
        raise RuntimeError(
            "Refusing to bind GUI to a non-loopback host without AUDORA_GUI_ALLOW_REMOTE=1."
        )

    if not _env_flag("AUDORA_GUI_REQUIRE_AUTH", default=False):
        raise RuntimeError(
            "Remote GUI requires AUDORA_GUI_REQUIRE_AUTH=1 to prevent unauthenticated access."
        )

    username = os.getenv("AUDORA_GUI_USERNAME", "").strip()
    password = os.getenv("AUDORA_GUI_PASSWORD", "").strip()
    if not username or not password:
        raise RuntimeError(
            "Remote GUI requires AUDORA_GUI_USERNAME and AUDORA_GUI_PASSWORD to be set."
        )


if __name__ == "__main__":
    host = os.getenv("AUDORA_GUI_HOST", "127.0.0.1")
    port = int(os.getenv("AUDORA_GUI_PORT", "8050"))
    debug = _env_flag("AUDORA_GUI_DEBUG", default=False)
    _validate_gui_security_policy(host)
    app.run(host=host, port=port, debug=debug)
