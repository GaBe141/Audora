#!/usr/bin/env python3
"""
Audora prototyping GUI - entry point.
Starts the Dash server at http://127.0.0.1:8050.

Security note:
    Set AUDORA_GUI_ADMIN_TOKEN before starting the GUI to enable protected actions.
"""

import os
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.app import GUI_ADMIN_TOKEN_ENV, app  # noqa: E402

if __name__ == "__main__":
    if not os.getenv(GUI_ADMIN_TOKEN_ENV, "").strip():
        print(
            f"Warning: {GUI_ADMIN_TOKEN_ENV} is not set; protected GUI actions are disabled.",
            file=sys.stderr,
        )
    app.run(host="127.0.0.1", port=8050, debug=False)
