"""Structured logging configuration for Audora Music Analytics Platform.

This module provides JSON-formatted logging with proper handlers for
file and console output, improving observability and debugging capabilities.
"""

import copy
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SENSITIVE_FIELD_PATTERN = re.compile(
    r"(api[_-]?key|authorization|bearer|client[_-]?secret|credential|password|refresh[_-]?token|secret|token)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/\-]+=*|"
    r"(bearer\s+)[A-Za-z0-9._~+/\-]+=*|"
    r"((?:api[_-]?key|authorization|client[_-]?secret|password|refresh[_-]?token|secret|token)\s+)"
    r"([^\s,;\"']+)|"
    r"([A-Za-z0-9_.-]*(?:api[_-]?key|authorization|client[_-]?secret|password|"
    r"refresh[_-]?token|secret|token)[A-Za-z0-9_.-]*\s*[:=]\s*)([^\s,;\"']+)"
)
REDACTED = "[REDACTED]"


def _redact_sensitive_match(match: re.Match[str]) -> str:
    """Preserve credential prefixes while removing secret values."""
    if match.group(1):
        return f"{match.group(1)}{REDACTED}"
    if match.group(2):
        return f"{match.group(2)}{REDACTED}"
    if match.group(3):
        return f"{match.group(3)}{REDACTED}"
    return f"{match.group(5)}{REDACTED}"


def _redact_sensitive_data(value: Any) -> Any:
    """Redact credentials from structured log data before emission."""
    if isinstance(value, dict):
        redacted = {}
        for key, nested_value in value.items():
            key_text = str(key)
            if SENSITIVE_FIELD_PATTERN.search(key_text):
                redacted[key] = REDACTED
            else:
                redacted[key] = _redact_sensitive_data(nested_value)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive_data(item) for item in value)

    if isinstance(value, str):
        return SENSITIVE_VALUE_PATTERN.sub(_redact_sensitive_match, value)

    return value


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging.

    This formatter outputs logs in JSON format which is easier to parse,
    search, and analyze using log aggregation tools.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as JSON.

        Args:
            record: The log record to format

        Returns:
            JSON-formatted log string
        """
        log_data: dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_sensitive_data(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
        }

        # Add exception information if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": (
                    _redact_sensitive_data(str(record.exc_info[1])) if record.exc_info[1] else None
                ),
                "traceback": _redact_sensitive_data(self.formatException(record.exc_info)),
            }

        # Add custom fields from 'extra' parameter
        if hasattr(record, "extra_fields"):
            log_data.update(_redact_sensitive_data(record.extra_fields))

        # Add any other custom attributes
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "stack_info",
                "extra_fields",
            ]:
                try:
                    if SENSITIVE_FIELD_PATTERN.search(str(key)):
                        log_data[key] = REDACTED
                    else:
                        log_data[key] = _redact_sensitive_data(value)
                except (TypeError, ValueError):
                    log_data[key] = _redact_sensitive_data(str(value))

        return json.dumps(log_data, default=str)


class RedactingFormatter(logging.Formatter):
    """Format log records after redacting credential-like values."""

    def format(self, record: logging.LogRecord) -> str:
        safe_record = copy.copy(record)
        safe_record.msg = _redact_sensitive_data(record.getMessage())
        safe_record.args = ()
        safe_record.getMessage = lambda: str(safe_record.msg)
        return super().format(safe_record)


class ColoredConsoleFormatter(RedactingFormatter):
    """Format log records with colors for console output.

    This formatter adds ANSI color codes for different log levels,
    improving readability in terminal output.
    """

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with colors.

        Args:
            record: The log record to format

        Returns:
            Colored log string
        """
        safe_record = copy.copy(record)
        safe_record.msg = _redact_sensitive_data(record.getMessage())
        safe_record.args = ()
        safe_record.getMessage = lambda: str(safe_record.msg)

        color = self.COLORS.get(safe_record.levelname, self.RESET)
        safe_record.levelname = f"{color}{self.BOLD}{safe_record.levelname}{self.RESET}"
        safe_record.name = f"{self.BOLD}{safe_record.name}{self.RESET}"

        return logging.Formatter.format(self, safe_record)


def setup_logging(
    log_dir: str | Path = "logs",
    log_level: str = "INFO",
    app_name: str = "audora",
    json_logs: bool = True,
    console_output: bool = True,
    file_output: bool = True,
) -> None:
    """Setup application logging with structured output.

    Args:
        log_dir: Directory to store log files
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        app_name: Application name for log file naming
        json_logs: Whether to use JSON format for file logs
        console_output: Whether to enable console logging
        file_output: Whether to enable file logging

    Example:
        ```python
        from core.logging_config import setup_logging

        # Setup logging
        setup_logging(
            log_dir="logs",
            log_level="DEBUG",
            app_name="audora",
            json_logs=True
        )

        # Use logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Application started", extra={"user": "admin"})
        ```
    """
    # Create log directory
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers = []

    # Console handler (human-readable with colors)
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        if sys.stdout.isatty():  # Use colors only in interactive terminals
            console_formatter = ColoredConsoleFormatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        else:
            console_formatter = RedactingFormatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handlers
    if file_output:
        timestamp = datetime.now().strftime("%Y%m%d")

        # Main log file (all levels)
        main_log_file = log_path / f"{app_name}_{timestamp}.log"
        main_handler = logging.FileHandler(main_log_file, encoding="utf-8")
        main_handler.setLevel(log_level)

        if json_logs:
            main_handler.setFormatter(JSONFormatter())
        else:
            main_handler.setFormatter(
                RedactingFormatter(
                    fmt="%(asctime)s - %(name)s - %(levelname)s - "
                    "%(module)s:%(funcName)s:%(lineno)d - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )

        root_logger.addHandler(main_handler)

        # Error log file (ERROR and CRITICAL only)
        error_log_file = log_path / f"{app_name}_errors_{timestamp}.log"
        error_handler = logging.FileHandler(error_log_file, encoding="utf-8")
        error_handler.setLevel(logging.ERROR)

        if json_logs:
            error_handler.setFormatter(JSONFormatter())
        else:
            error_handler.setFormatter(
                RedactingFormatter(
                    fmt="%(asctime)s - %(name)s - %(levelname)s - "
                    "%(module)s:%(funcName)s:%(lineno)d - %(message)s\n"
                    "Exception: %(exc_info)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )

        root_logger.addHandler(error_handler)

    # Configure third-party loggers to reduce noise
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("spotipy").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    # Log successful setup
    logger = logging.getLogger(__name__)
    logger.info(
        f"Logging configured: level={log_level}, "
        f"console={console_output}, file={file_output}, json={json_logs}"
    )


def get_logger(name: str, extra_fields: dict[str, Any] | None = None) -> logging.LoggerAdapter:
    """Get a logger with optional extra fields.

    Args:
        name: Logger name (usually __name__)
        extra_fields: Dictionary of fields to include in all log messages

    Returns:
        LoggerAdapter with extra fields

    Example:
        ```python
        logger = get_logger(__name__, {"component": "analytics"})
        logger.info("Processing data", extra={"records": 1000})
        ```
    """
    logger = logging.getLogger(name)

    if extra_fields:
        return logging.LoggerAdapter(logger, {"extra_fields": extra_fields})

    return logging.LoggerAdapter(logger, {})


# Example usage context manager for structured logging
class LogContext:
    """Context manager for adding temporary log context.

    Example:
        ```python
        with LogContext(user_id="123", session_id="abc"):
            logger.info("User action performed")
            # Log will include user_id and session_id
        ```
    """

    _context: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        """Initialize log context.

        Args:
            **kwargs: Key-value pairs to add to log context
        """
        self.context = kwargs
        self.previous_context: dict[str, Any] = {}

    def __enter__(self) -> "LogContext":
        """Enter the context."""
        self.previous_context = LogContext._context.copy()
        LogContext._context.update(self.context)
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: Any) -> None:
        """Exit the context."""
        LogContext._context = self.previous_context

    @classmethod
    def get_context(cls) -> dict[str, Any]:
        """Get current log context.

        Returns:
            Current context dictionary
        """
        return cls._context.copy()


__all__ = [
    "setup_logging",
    "get_logger",
    "JSONFormatter",
    "RedactingFormatter",
    "ColoredConsoleFormatter",
    "LogContext",
]
