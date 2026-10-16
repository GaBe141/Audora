"""Shared utility functions for the Audora project."""

import errno
import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_LEADING_FORMULA_WHITESPACE = " \t\r\n"

# Re-export for convenience
try:
    import pandas as pd

    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


def _is_inside(path: Path, root: Path) -> bool:
    """Return True when path is root or a path under root."""
    return path == root or path.is_relative_to(root)


def resolve_within_project(path: Path | str) -> Path:
    """Resolve a path and reject targets outside the project or via symlinks.

    Relative paths are anchored at the project root so a caller cannot escape by
    changing the process working directory.
    """
    raw = Path(path)
    candidate = raw if raw.is_absolute() else PROJECT_ROOT / raw
    if candidate.is_symlink():
        raise ValueError(f"Symlinks are not allowed: {path}")
    resolved = candidate.resolve(strict=False)
    root = PROJECT_ROOT.resolve()
    if not _is_inside(resolved, root):
        raise ValueError(f"Path escapes the project directory: {path}")
    return resolved


def confine_child_path(directory: Path | str, name: str) -> Path:
    """Join a single file name under a project directory.

    Absolute names, parent segments, separators, and symlinks are rejected.
    """
    if not isinstance(name, str) or name != Path(name).name or name in {"", ".", ".."}:
        raise ValueError("Invalid data file name")
    if any(separator in name for separator in ("/", "\\", "\x00")):
        raise ValueError("Invalid data file name")

    base = resolve_within_project(directory)
    candidate = base / name
    if candidate.is_symlink():
        raise ValueError("Symlinked data files are not allowed")
    resolved = candidate.resolve(strict=False)
    if not _is_inside(resolved, base):
        raise ValueError("Path escapes the data directory")
    return resolved


def is_allowed_storage_path(path: Path) -> bool:
    """Allow project files and the system temp dir used by tests."""
    resolved = path.resolve(strict=False)
    roots = (PROJECT_ROOT.resolve(), Path(tempfile.gettempdir()).resolve())
    return any(_is_inside(resolved, root) for root in roots)


def open_nofollow(path: Path, mode: str):
    """Open a file without following a symlink at the final path component."""
    text_mode = mode.replace("b", "")
    if any(flag in text_mode for flag in ("w", "a", "x")):
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
        if "a" in text_mode:
            flags |= os.O_APPEND
        else:
            flags |= os.O_TRUNC
        fd = os.open(path, flags, 0o600)
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    if "b" in mode:
        return os.fdopen(fd, mode)
    return os.fdopen(fd, mode, encoding="utf-8")


def neutralize_csv_value(value: Any) -> Any:
    """Prefix spreadsheet formula cells so exported CSV cannot execute them."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip(_LEADING_FORMULA_WHITESPACE)
    if stripped.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def neutralize_csv_frame(df: Any) -> Any:
    """Neutralize formula injection in every column, including pandas string dtypes."""
    if not HAS_PANDAS:
        raise ImportError("pandas is required for neutralize_csv_frame")
    neutralized = df.copy()
    for column in neutralized.columns:
        neutralized[column] = neutralized[column].map(neutralize_csv_value)
    return neutralized


# JSON utilities
def read_json(path: Path | str, default: Any = None) -> Any:
    """
    Read JSON file safely.

    Args:
        path: Path to JSON file
        default: Value to return if file doesn't exist or is invalid

    Returns:
        Parsed JSON data or default value

    Raises:
        json.JSONDecodeError: If JSON is malformed and no default provided
    """
    path = resolve_within_project(path)
    try:
        with open_nofollow(path, "r") as fh:
            return json.load(fh)
    except FileNotFoundError:
        if default is not None:
            logger.warning(f"JSON file not found: {path}, using default")
            return default
        raise
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError(f"Symlinks are not allowed: {path}") from e
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {path}: {e}")
        if default is not None:
            return default
        raise


def write_json(
    path: Path | str,
    obj: Any,
    indent: int = 2,
    ensure_ascii: bool = False,
    create_dirs: bool = True,
) -> Path:
    """
    Write JSON file safely.

    Args:
        path: Path to write JSON to
        obj: Object to serialize
        indent: JSON indentation level
        ensure_ascii: Whether to escape non-ASCII characters
        create_dirs: Whether to create parent directories

    Returns:
        Path object of the written file

    Raises:
        Exception: If writing fails
    """
    path = resolve_within_project(path)
    try:
        if create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)

        with open_nofollow(path, "w") as fh:
            json.dump(obj, fh, indent=indent, ensure_ascii=ensure_ascii, default=str)
        if os.name != "nt":
            path.chmod(0o600)

        logger.debug(f"Wrote JSON to {path}")
        return path
    except Exception as e:
        logger.error(f"Failed to write JSON to {path}: {e}")
        raise


def save_dataframe(df: Any, filepath: Path | str, create_dirs: bool = True) -> Path:  # pd.DataFrame
    """
    Save DataFrame to CSV with consistent settings.

    Args:
        df: DataFrame to save
        filepath: Path to save CSV to
        create_dirs: Whether to create parent directories

    Returns:
        Path object of the written file
    """
    filepath = resolve_within_project(filepath)

    if create_dirs:
        filepath.parent.mkdir(parents=True, exist_ok=True)

    neutralize_csv_frame(df).to_csv(filepath, index=False)
    logger.debug(f"Saved DataFrame to {filepath}")
    return filepath


def get_timestamp_filename(prefix: str = "", suffix: str = "") -> str:
    """
    Generate a filename with current timestamp.

    Args:
        prefix: String to prepend to timestamp
        suffix: String to append after timestamp

    Returns:
        Filename with format: {prefix}_{timestamp}_{suffix}

    Examples:
        >>> get_timestamp_filename("report", ".json")
        'report_20251010_143052.json'
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parts = [p for p in [prefix, timestamp, suffix] if p]
    return "_".join(parts) if len(parts) > 1 else timestamp


# Data validation helpers
def validate_track_data(track: dict[str, Any], required_fields: list[str] | None = None) -> bool:
    """
    Validate track data structure.

    Args:
        track: Track dictionary to validate
        required_fields: List of required field names (default: id, name, artist)

    Returns:
        True if valid, False otherwise
    """
    if required_fields is None:
        required_fields = ["id", "name", "artist"]

    return all(field in track and track[field] for field in required_fields)


def safe_get_nested(data: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    """
    Safely get nested dictionary value.

    Args:
        data: Dictionary to traverse
        keys: List of keys to traverse in order
        default: Value to return if any key is missing

    Returns:
        Nested value or default

    Examples:
        >>> data = {"a": {"b": {"c": 42}}}
        >>> safe_get_nested(data, ["a", "b", "c"])
        42
        >>> safe_get_nested(data, ["a", "x", "y"], default=0)
        0
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


# DataFrame utilities (requires pandas)
def load_dataframe(
    filepath: Path | str,
    required_columns: list[str] | None = None,
    default_empty: bool = True,
) -> Any:  # pd.DataFrame | None
    """
    Load DataFrame from CSV with error handling.

    Args:
        filepath: Path to CSV file
        required_columns: List of columns that must be present
        default_empty: Return empty DataFrame instead of None if file doesn't exist

    Returns:
        DataFrame or empty DataFrame (if default_empty=True) or None

    Examples:
        >>> df = load_dataframe("data/tracks.csv", required_columns=["id", "name"])
        >>> df = load_dataframe("missing.csv", default_empty=False)  # Returns None
    """
    if not HAS_PANDAS:
        raise ImportError("pandas is required for load_dataframe")

    filepath = resolve_within_project(filepath)

    if not filepath.exists() or filepath.is_symlink():
        logger.warning(f"CSV file not found: {filepath}")
        return pd.DataFrame() if default_empty else None

    try:
        with open_nofollow(filepath, "rb") as fh:
            df = pd.read_csv(fh)

        # Validate required columns
        if required_columns:
            missing = set(required_columns) - set(df.columns)
            if missing:
                logger.error(f"Missing required columns in {filepath}: {missing}")
                return pd.DataFrame() if default_empty else None

        logger.debug(f"Loaded DataFrame from {filepath} ({len(df)} rows)")
        return df

    except Exception as e:
        logger.error(f"Failed to load CSV from {filepath}: {e}")
        return pd.DataFrame() if default_empty else None


def ensure_datetime_column(
    df: Any,  # pd.DataFrame
    column: str,
    date_formats: list[str] | None = None,
    errors: str = "coerce",
) -> Any:  # pd.DataFrame
    """
    Convert DataFrame column to datetime with fallback handling.

    Args:
        df: DataFrame to modify
        column: Column name to convert
        date_formats: List of date formats to try (None = auto-detect)
        errors: How to handle errors ('coerce', 'raise', 'ignore')

    Returns:
        DataFrame with converted column (modifies in place)

    Examples:
        >>> df = ensure_datetime_column(df, "played_at")
        >>> df = ensure_datetime_column(df, "timestamp", date_formats=["%Y-%m-%d"])
    """
    if not HAS_PANDAS:
        raise ImportError("pandas is required for ensure_datetime_column")

    if column not in df.columns:
        logger.warning(f"Column {column} not found in DataFrame")
        return df

    # Already datetime?
    if pd.api.types.is_datetime64_any_dtype(df[column]):
        return df

    # Try conversion
    try:
        if date_formats:
            # Try each format
            for fmt in date_formats:
                try:
                    df[column] = pd.to_datetime(df[column], format=fmt, errors=errors)
                    logger.debug(f"Converted {column} to datetime using format {fmt}")
                    return df
                except Exception:
                    continue
            # If all fail, use auto-detect
            df[column] = pd.to_datetime(df[column], errors=errors)
        else:
            # Auto-detect
            df[column] = pd.to_datetime(df[column], errors=errors)

        logger.debug(f"Converted {column} to datetime")
        return df

    except Exception as e:
        logger.error(f"Failed to convert {column} to datetime: {e}")
        return df


# Timestamp utilities
def get_iso_timestamp() -> str:
    """
    Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string

    Examples:
        >>> ts = get_iso_timestamp()
        '2025-10-10T14:30:52.123456'
    """
    return datetime.now().isoformat()


def get_date_string(fmt: str = "%Y-%m-%d") -> str:
    """
    Get current date as formatted string.

    Args:
        fmt: strftime format string

    Returns:
        Formatted date string

    Examples:
        >>> get_date_string()
        '2025-10-10'
        >>> get_date_string("%Y%m%d")
        '20251010'
    """
    return datetime.now().strftime(fmt)


# Report generation helpers
def save_report(
    data: dict[str, Any],
    filename: str | None = None,
    prefix: str = "report",
    output_dir: str = "data/reports",
    add_timestamp: bool = True,
) -> Path:
    """
    Save a report/analysis to JSON with automatic timestamping and directory creation.

    Args:
        data: Dictionary data to save
        filename: Custom filename (if None, auto-generates with timestamp)
        prefix: Prefix for auto-generated filename
        output_dir: Directory to save report to
        add_timestamp: Whether to add timestamp to data (as 'timestamp' key)

    Returns:
        Path to saved report file

    Examples:
        >>> save_report({"analysis": "results"}, prefix="analytics")
        PosixPath('data/reports/analytics_20251010_143052.json')
        >>> save_report({"data": "test"}, filename="custom_report.json")
        PosixPath('data/reports/custom_report.json')
    """
    # Auto-generate filename if not provided
    if filename is None:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp_str}.json"

    # Create full path inside the project
    output_path = resolve_within_project(output_dir)
    safe_name = confine_child_path(output_path, Path(filename).name)
    output_path.mkdir(parents=True, exist_ok=True)
    filepath = safe_name

    # Add timestamp to data if requested
    if add_timestamp and "timestamp" not in data:
        data = {**data, "timestamp": get_iso_timestamp()}

    # Save using write_json
    write_json(filepath, data)
    logger.info(f"Saved report to {filepath}")

    return filepath
