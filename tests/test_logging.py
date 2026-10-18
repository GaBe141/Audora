"""Tests for core logging configuration (JSONFormatter, LogContext, get_logger, setup_logging)."""

import json
import logging
import sys
from io import StringIO

from core.logging_config import (
    ColoredConsoleFormatter,
    JSONFormatter,
    LogContext,
    RedactingFormatter,
    get_logger,
    setup_logging,
)

_DISCORD_WEBHOOK = "https://discord.com/api/v10/webhooks/123/super-secret-token"


def _restore_root(previous_handlers: list[logging.Handler], previous_level: int) -> None:
    root = logging.getLogger()
    for handler in root.handlers:
        handler.close()
    root.handlers = previous_handlers
    root.setLevel(previous_level)


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

    def test_format_redacts_webhook_urls(self):
        formatter = JSONFormatter()
        secret = "https://discord.com/api/v10/webhooks/123/super-secret-token"
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="delivery failed",
            args=(),
            exc_info=None,
        )
        record.funcName = "f"
        record.module = "m"
        record.thread = 0
        record.threadName = "Main"
        record.getMessage = lambda: f"delivery failed {secret}"
        output = formatter.format(record)
        assert "super-secret-token" not in output
        assert "REDACTED" in output

    def test_format_redacts_nested_webhook_urls(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="delivery failed",
            args=(),
            exc_info=None,
        )
        record.funcName = "f"
        record.module = "m"
        record.thread = 0
        record.threadName = "Main"
        record.getMessage = lambda: "delivery failed"
        record.extra_fields = {"payload": {"webhook_url": _DISCORD_WEBHOOK}}
        output = formatter.format(record)
        assert "super-secret-token" not in output
        assert "REDACTED" in output
        assert json.loads(output)["payload"]["webhook_url"].endswith("REDACTED")


class TestRedactingFormatter:
    """Plain log lines must not keep webhook URLs or query secrets."""

    def test_format_redacts_webhook_and_query_secrets(self):
        formatter = RedactingFormatter(fmt="%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="failed %s api_key=%s",
            args=(_DISCORD_WEBHOOK, "lastfm-secret-key"),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "super-secret-token" not in output
        assert "lastfm-secret-key" not in output
        assert "https://charts.spotify.com/chart" in formatter.format(
            logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg="see https://charts.spotify.com/chart",
                args=(),
                exc_info=None,
            )
        )


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


class _CapturingStream:
    """Stdout stand-in that reports itself as a non-interactive pipe."""

    def __init__(self) -> None:
        self.buffer = StringIO()

    def write(self, data: str) -> int:
        return self.buffer.write(data)

    def flush(self) -> None:
        self.buffer.flush()

    def isatty(self) -> bool:
        return False


class TestSetupLogging:
    """Smoke test for setup_logging - no file output to avoid leaving files."""

    def test_setup_logging_smoke(self, tmp_path):
        root = logging.getLogger()
        previous_handlers = root.handlers[:]
        previous_level = root.level
        try:
            setup_logging(
                log_dir=str(tmp_path),
                log_level="DEBUG",
                app_name="audora_test",
                json_logs=True,
                console_output=False,
                file_output=False,
            )
            assert root.level == logging.DEBUG
        finally:
            _restore_root(previous_handlers, previous_level)

    def test_noninteractive_console_redacts_secrets(self, monkeypatch, tmp_path):
        stream = _CapturingStream()
        monkeypatch.setattr(sys, "stdout", stream)
        root = logging.getLogger()
        previous_handlers = root.handlers[:]
        previous_level = root.level
        try:
            setup_logging(
                log_dir=str(tmp_path),
                log_level="INFO",
                app_name="audora_test",
                console_output=True,
                file_output=False,
            )
            logging.getLogger("audora.test").error("delivery failed %s", _DISCORD_WEBHOOK)
            for handler in root.handlers:
                handler.flush()
            output = stream.buffer.getvalue()
            assert "super-secret-token" not in output
            assert "REDACTED" in output
        finally:
            _restore_root(previous_handlers, previous_level)

    def test_plain_file_logs_redact_secrets(self, tmp_path):
        root = logging.getLogger()
        previous_handlers = root.handlers[:]
        previous_level = root.level
        try:
            setup_logging(
                log_dir=str(tmp_path),
                log_level="INFO",
                app_name="audora_test",
                json_logs=False,
                console_output=False,
                file_output=True,
            )
            logging.getLogger("audora.test").error("delivery failed %s", _DISCORD_WEBHOOK)
            text = ""
            for handler in root.handlers:
                handler.flush()
            for path in tmp_path.glob("*.log"):
                text += path.read_text(encoding="utf-8")
            assert "super-secret-token" not in text
            assert "REDACTED" in text
        finally:
            _restore_root(previous_handlers, previous_level)
