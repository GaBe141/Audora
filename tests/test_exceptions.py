"""Tests for core exception hierarchy and handle_errors decorator."""

import logging

import pytest

from core.exceptions import (
    APIRateLimitError,
    AudoraException,
    DatabaseConnectionError,
    InsufficientDataError,
    MissingCredentialsError,
    NotificationDeliveryError,
    handle_errors,
)


class TestAudoraException:
    """Tests for base AudoraException and subclasses."""

    def test_base_exception_message_and_error_code(self):
        exc = AudoraException(message="Test message", error_code="TEST_CODE")
        assert exc.message == "Test message"
        assert exc.error_code == "TEST_CODE"
        assert exc.details == {}

    def test_base_exception_with_details(self):
        exc = AudoraException(message="Msg", error_code="CODE", details={"key": "value"})
        assert exc.details == {"key": "value"}

    def test_str_without_details(self):
        exc = AudoraException(message="Msg", error_code="CODE")
        s = str(exc)
        assert "[CODE]" in s
        assert "Msg" in s

    def test_str_with_details(self):
        exc = AudoraException(message="Msg", error_code="CODE", details={"a": 1})
        s = str(exc)
        assert "Details:" in s
        assert "a" in s or "1" in s

    def test_to_dict(self):
        exc = AudoraException(message="Msg", error_code="CODE", details={"x": "y"})
        d = exc.to_dict()
        assert d["error_code"] == "CODE"
        assert d["message"] == "Msg"
        assert d["details"] == {"x": "y"}
        assert d["exception_type"] == "AudoraException"


class TestExceptionSubclasses:
    """Test that subclasses set correct error_code and to_dict."""

    @pytest.mark.parametrize(
        "exc_class,expected_code",
        [
            (DatabaseConnectionError, "DB_CONNECTION_FAILED"),
            (APIRateLimitError, "API_RATE_LIMIT_EXCEEDED"),
            (InsufficientDataError, "INSUFFICIENT_DATA"),
            (NotificationDeliveryError, "NOTIFICATION_DELIVERY_FAILED"),
            (MissingCredentialsError, "MISSING_CREDENTIALS"),
        ],
    )
    def test_subclass_error_codes(self, exc_class, expected_code):
        exc = exc_class("Something failed", details={"extra": 1})
        assert exc.error_code == expected_code
        d = exc.to_dict()
        assert d["error_code"] == expected_code
        assert d["message"] == "Something failed"
        assert d["details"] == {"extra": 1}
        assert d["exception_type"] == exc_class.__name__


class TestHandleErrors:
    """Tests for handle_errors decorator."""

    def test_reraises_when_reraise_true(self):
        logger = logging.getLogger("test_handle_errors_rerase")
        logger.setLevel(logging.DEBUG)

        @handle_errors(InsufficientDataError, logger, reraise=True)
        def failing():
            raise InsufficientDataError("Not enough data", details={"n": 0})

        with pytest.raises(InsufficientDataError) as exc_info:
            failing()
        assert exc_info.value.message == "Not enough data"

    def test_returns_none_when_reraise_false(self):
        logger = logging.getLogger("test_handle_errors_no_rerase")

        @handle_errors(InsufficientDataError, logger, reraise=False)
        def failing():
            raise InsufficientDataError("Not enough data")

        result = failing()
        assert result is None

    def test_passes_through_return_value_when_no_error(self):
        logger = logging.getLogger("test_handle_errors_pass")

        @handle_errors(InsufficientDataError, logger, reraise=True)
        def success():
            return 42

        assert success() == 42

    def test_logger_called_on_caught_exception(self, caplog):
        logger = logging.getLogger("test_handle_errors_log")
        caplog.set_level(logging.ERROR, logger="test_handle_errors_log")

        @handle_errors(InsufficientDataError, logger, reraise=False)
        def failing():
            raise InsufficientDataError("Not enough data", details={"n": 0})

        failing()
        assert any("failing" in rec.message for rec in caplog.records)
        assert any("Not enough data" in rec.message for rec in caplog.records)
