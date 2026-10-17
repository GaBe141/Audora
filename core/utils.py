"""Shared utility functions for the Audora project."""

import errno
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_CSV_FORMULA_STARTS = ("=", "+", "-", "@")

# Re-export for convenience
try:
    import pandas as pd

    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


def confine_relative_path(path: Path | str, *, base: Path | None = None) -> Path:
    """Resolve a relative path and keep it inside the project root.

    Absolute paths and a symlinked final component are rejected.
    """
    root = (base if base is not None else PROJECT_ROOT).resolve()
    raw = Path(path)
    if raw.is_absolute():
        raise ValueError("Absolute paths are not allowed")
    candidate = root / raw
    if candidate.is_symlink():
        raise ValueError("Refusing to use a symlinked path")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes the project root") from exc
    return resolved


def _nofollow_flags(flags: int) -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return flags | os.O_NOFOLLOW
    return flags


def _raise_if_symlink_error(exc: OSError) -> None:
    if exc.errno == errno.ELOOP:
        raise ValueError("Refusing to follow a symlink") from exc


def read_nofollow_text(path: Path | str) -> str:
    """Read a text file without following a final-component symlink."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked file: {file_path}")
    fd = os.open(file_path, _nofollow_flags(os.O_RDONLY))
    try:
        handle = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        with handle:
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def read_nofollow_bytes(path: Path | str) -> bytes:
    """Read a file without following a final-component symlink."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked file: {file_path}")
    fd = os.open(file_path, _nofollow_flags(os.O_RDONLY))
    try:
        handle = os.fdopen(fd, "rb")
        fd = -1
        with handle:
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def write_private_text(path: Path | str, content: str) -> Path:
    """Write text with mode 600 without following a swapped-in symlink."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to write through a symlink: {file_path}")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    flags = _nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    fd = os.open(file_path, flags, 0o600)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with handle:
            handle.write(content)
    finally:
        if fd >= 0:
            os.close(fd)
    return file_path


def ensure_private_file(path: Path | str) -> Path:
    """Create a secret file if needed and force mode 600 without following a symlink."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError("Refusing to use a symlinked secret file")
    if not file_path.exists():
        return write_private_text(file_path, "")
    if os.name == "nt":
        return file_path
    fd = os.open(file_path, _nofollow_flags(os.O_RDONLY))
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return file_path


def neutralize_csv_value(value: Any) -> Any:
    """Prefix spreadsheet formula cells so exported CSV cannot execute them."""
    if not isinstance(value, str) or value == "":
        return value
    probe = value.lstrip(" \t\r")
    if probe.startswith(_CSV_FORMULA_STARTS):
        return "'" + value
    return value


def neutralize_csv_frame(df: Any) -> Any:
    """Neutralize formula-looking cells in every column of a DataFrame."""
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
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked JSON file: {path}")
    fd = -1
    try:
        fd = os.open(path, _nofollow_flags(os.O_RDONLY))
        handle = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        with handle:
            return json.load(handle)
    except FileNotFoundError:
        if default is not None:
            logger.warning(f"JSON file not found: {path}, using default")
            return default
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {path}: {e}")
        if default is not None:
            return default
        raise
    except OSError as exc:
        _raise_if_symlink_error(exc)
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def write_json(
    path: Path | str,
    obj: Any,
    indent: int = 2,
    ensure_ascii: bool = False,
    create_dirs: bool = True,
    *,
    private: bool = False,
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
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Refusing to write a symlinked JSON file: {path}")
    fd = -1
    try:
        if create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)

        flags = _nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        mode = 0o600 if private else 0o644
        fd = os.open(path, flags, mode)
        if private and os.name != "nt":
            os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with handle:
            json.dump(obj, handle, indent=indent, ensure_ascii=ensure_ascii, default=str)

        logger.debug(f"Wrote JSON to {path}")
        return path
    except OSError as exc:
        _raise_if_symlink_error(exc)
        logger.error(f"Failed to write JSON to {path}: {exc}")
        raise
    except Exception as e:
        logger.error(f"Failed to write JSON to {path}: {e}")
        raise
    finally:
        if fd >= 0:
            os.close(fd)


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
    filepath = Path(filepath)
    if filepath.is_symlink():
        raise ValueError(f"Refusing to write CSV through a symlink: {filepath}")

    if create_dirs:
        filepath.parent.mkdir(parents=True, exist_ok=True)

    frame = neutralize_csv_frame(df)
    fd = os.open(filepath, _nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_TRUNC), 0o644)
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8", newline="")
        fd = -1
        with handle:
            frame.to_csv(handle, index=False)
    finally:
        if fd >= 0:
            os.close(fd)
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

    filepath = Path(filepath)

    if not filepath.exists():
        logger.warning(f"CSV file not found: {filepath}")
        return pd.DataFrame() if default_empty else None

    try:
        df = pd.read_csv(filepath)

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

    safe_name = Path(filename).name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Invalid report filename")
    filepath = confine_relative_path(Path(output_dir) / safe_name)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Add timestamp to data if requested
    if add_timestamp and "timestamp" not in data:
        data = {**data, "timestamp": get_iso_timestamp()}

    # Save using write_json
    write_json(filepath, data)
    logger.info(f"Saved report to {filepath}")

    return filepath
