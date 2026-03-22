"""Helpers for constraining filesystem writes to safe base directories."""

from datetime import datetime
from pathlib import Path

DEFAULT_REPORTS_DIR = (Path(__file__).resolve().parent.parent / "data").resolve()


def resolve_safe_report_path(
    custom_filename: str | None, base_dir: Path = DEFAULT_REPORTS_DIR
) -> Path:
    """Resolve report output path and prevent path traversal."""
    base_path = base_dir.resolve()
    base_path.mkdir(parents=True, exist_ok=True)

    if not custom_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return base_path / f"comprehensive_discovery_report_{timestamp}.json"

    requested = Path(custom_filename)
    if requested.is_absolute():
        raise ValueError("Absolute report paths are not allowed")

    resolved = (base_path / requested).resolve()
    try:
        resolved.relative_to(base_path)
    except ValueError as exc:
        raise ValueError("Report path must stay within the data directory") from exc
    return resolved
