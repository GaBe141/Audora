"""Structured logging configuration for Audora Music Analytics Platform.

This module provides JSON-formatted logging with proper handlers for
file and console output, improving observability and debugging capabilities.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|authorization)(=|%3D|:\s*Bearer\s+)[^&\s\"']+"
)
SENSITIVE_KEYWORDS = ("api_key", "apikey", "token", "secret", "password", "authorization")


def redact_sensitive_data(value: Any) -> Any:
    """Redact common credential fields from values before logging."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(keyword in str(key).lower() for keyword in SENSITIVE_KEYWORDS)
            else redact_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return SENSITIVE_VALUE_PATTERN.sub(r"\1\2[REDACTED]", value)
    return value


class RedactingFilter(logging.Filter):
    """Remove likely secrets from log messages, arguments, and exception text."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_sensitive_data(record.msg)
        record.args = redact_sensitive_data(record.args)
        if record.exc_info and record.exc_info[1]:
            record.exc_text = None
        return True


def _prepare_secure_log_file(path: Path) -> None:
    """Create a log file with owner-only permissions before handlers use it."""
    if os.name == "nt":
        path.touch(exist_ok=True)
        return

    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


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
            "message": redact_sensitive_data(record.getMessage()),
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
                "message": redact_sensitive_data(str(record.exc_info[1]))
                if record.exc_info[1]
                else None,
                "traceback": redact_sensitive_data(self.formatException(record.exc_info)),
            }

        # Add custom fields from 'extra' parameter
        if hasattr(record, "extra_fields"):
            log_data.update(redact_sensitive_data(record.extra_fields))

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
                    log_data[key] = redact_sensitive_data(value)
                except (TypeError, ValueError):
                    log_data[key] = redact_sensitive_data(str(value))

        return json.dumps(log_data, default=str)


class ColoredConsoleFormatter(logging.Formatter):
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
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{self.BOLD}{record.levelname}{self.RESET}"
        record.name = f"{self.BOLD}{record.name}{self.RESET}"

        return super().format(record)


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
        console_handler.addFilter(RedactingFilter())

        if sys.stdout.isatty():  # Use colors only in interactive terminals
            console_formatter = ColoredConsoleFormatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        else:
            console_formatter = logging.Formatter(
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
        _prepare_secure_log_file(main_log_file)
        main_handler = logging.FileHandler(main_log_file, encoding="utf-8")
        main_handler.setLevel(log_level)
        main_handler.addFilter(RedactingFilter())

        if json_logs:
            main_handler.setFormatter(JSONFormatter())
        else:
            main_handler.setFormatter(
                logging.Formatter(
                    fmt="%(asctime)s - %(name)s - %(levelname)s - "
                    "%(module)s:%(funcName)s:%(lineno)d - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )

        root_logger.addHandler(main_handler)

        # Error log file (ERROR and CRITICAL only)
        error_log_file = log_path / f"{app_name}_errors_{timestamp}.log"
        _prepare_secure_log_file(error_log_file)
        error_handler = logging.FileHandler(error_log_file, encoding="utf-8")
        error_handler.setLevel(logging.ERROR)
        error_handler.addFilter(RedactingFilter())

        if json_logs:
            error_handler.setFormatter(JSONFormatter())
        else:
            error_handler.setFormatter(
                logging.Formatter(
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
    "ColoredConsoleFormatter",
    "LogContext",
]
