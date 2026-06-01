#!/usr/bin/env python3
"""
Audora prototyping GUI - entry point.
Starts the Dash server at http://127.0.0.1:8050
"""

import os
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.app import app  # noqa: E402

if __name__ == "__main__":
    if os.getenv("AUDORA_ENABLE_GUI", "").strip().lower() not in {"1", "true", "yes", "on"}:
        print("Audora GUI is disabled by default because it can run local project actions.")
        print("Set AUDORA_ENABLE_GUI=1 to start it on http://127.0.0.1:8050.")
        sys.exit(1)

    app.run(host="127.0.0.1", port=8050, debug=False)
