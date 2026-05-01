"""Tests for core logging configuration (JSONFormatter, LogContext, get_logger, setup_logging)."""

import json
import logging
from io import StringIO

from core.logging_config import (
    ColoredConsoleFormatter,
    JSONFormatter,
    LogContext,
    RedactingFormatter,
    get_logger,
    setup_logging,
)


class TestJSONFormatter:
    """Tests for JSONFormatter."""

    def test_format_includes_required_keys(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="",
            lineno=10,
            msg="Hello %s",
            args=("world",),
            exc_info=None,
        )
        record.funcName = "test_func"
        record.module = "test_module"
        record.thread = 1
        record.threadName = "MainThread"
        record.getMessage = lambda: "Hello world"
        output = formatter.format(record)
        data = json.loads(output)
        assert "timestamp" in data
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "Hello world"
        assert data["module"] == "test_module"
        assert data["function"] == "test_func"
        assert data["line"] == 10

    def test_format_includes_exception_when_exc_info_set(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            exc_info = __import__("sys").exc_info()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Failed",
            args=(),
            exc_info=exc_info,
        )
        record.funcName = "f"
        record.module = "m"
        record.thread = 0
        record.threadName = "Main"
        record.getMessage = lambda: "Failed"
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert data["exception"]["type"] == "ValueError"
        assert "test error" in (data["exception"].get("message") or "")

    def test_format_redacts_sensitive_values(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Using token secret-token-123 and password=s3cr3t",
            args=(),
            exc_info=None,
        )
        record.funcName = "f"
        record.module = "m"
        record.thread = 0
        record.threadName = "Main"
        record.api_key = "api-key-123"
        record.extra_fields = {"nested": {"client_secret": "super-secret"}}
        output = formatter.format(record)
        data = json.loads(output)
        serialized = json.dumps(data)

        assert "secret-token-123" not in serialized
        assert "s3cr3t" not in serialized
        assert "api-key-123" not in serialized
        assert "super-secret" not in serialized
        assert data["api_key"] == "[REDACTED]"
        assert data["nested"]["client_secret"] == "[REDACTED]"


class TestColoredConsoleFormatter:
    """Tests for ColoredConsoleFormatter - at least message and level appear."""

    def test_format_contains_message_and_level(self):
        formatter = ColoredConsoleFormatter(fmt="%(levelname)s - %(message)s", datefmt="")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.getMessage = lambda: "Test message"
        output = formatter.format(record)
        assert "Test message" in output
        assert "INFO" in output

    def test_format_redacts_sensitive_values(self):
        formatter = ColoredConsoleFormatter(fmt="%(levelname)s - %(message)s", datefmt="")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authorization: Bearer secret-token-123",
            args=(),
            exc_info=None,
        )
        record.getMessage = lambda: "Authorization: Bearer secret-token-123"
        output = formatter.format(record)
        assert "secret-token-123" not in output
        assert "[REDACTED]" in output


class TestRedactingFormatter:
    """Tests for plain-text formatter redaction."""

    def test_format_redacts_sensitive_values(self):
        formatter = RedactingFormatter(fmt="%(levelname)s - %(message)s", datefmt="")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="password=s3cr3t",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "s3cr3t" not in output
        assert "[REDACTED]" in output


class TestLogContext:
    """Tests for LogContext context manager."""

    def test_get_context_contains_kwargs_inside_block(self):
        with LogContext(user_id="123", session_id="abc"):
            ctx = LogContext.get_context()
            assert ctx.get("user_id") == "123"
            assert ctx.get("session_id") == "abc"

    def test_context_restored_after_exit(self):
        LogContext._context = {}
        with LogContext(inside="yes"):
            assert LogContext.get_context().get("inside") == "yes"
        assert LogContext.get_context().get("inside") is None

    def test_nested_context_restores_previous(self):
        LogContext._context = {}
        with LogContext(outer=1):
            assert LogContext.get_context().get("outer") == 1
            with LogContext(inner=2):
                assert LogContext.get_context().get("outer") == 1
                assert LogContext.get_context().get("inner") == 2
            assert LogContext.get_context().get("inner") is None
            assert LogContext.get_context().get("outer") == 1
        assert LogContext.get_context().get("outer") is None


class TestGetLogger:
    """Tests for get_logger with optional extra_fields."""

    def test_get_logger_without_extra_fields(self):
        logger = get_logger(__name__)
        assert logger is not None
        # Log and capture
        buf = StringIO()
        h = logging.StreamHandler(buf)
        root = logging.getLogger(__name__)
        root.addHandler(h)
        root.setLevel(logging.DEBUG)
        logger.info("msg")
        root.removeHandler(h)
        assert "msg" in buf.getvalue()

    def test_get_logger_with_extra_fields(self):
        logger = get_logger(__name__, extra_fields={"component": "analytics"})
        assert logger.extra == {"extra_fields": {"component": "analytics"}}


class TestSetupLogging:
    """Smoke test for setup_logging - no file output to avoid leaving files."""

    def test_setup_logging_smoke(self, tmp_path):
        setup_logging(
            log_dir=str(tmp_path),
            log_level="DEBUG",
            app_name="audora_test",
            json_logs=True,
            console_output=False,
            file_output=False,
        )
        root = logging.getLogger()
        assert root.level == logging.DEBUG
