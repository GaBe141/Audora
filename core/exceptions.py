"""Custom exception hierarchy for Audora Music Analytics Platform.

This module provides a comprehensive exception system for better error handling
and debugging across the application.
"""

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar


class AudoraException(Exception):
    """Base exception for all Audora-specific errors.

    Attributes:
        message: Human-readable error message
        error_code: Machine-readable error code for programmatic handling
        details: Additional context and debugging information
    """

    def __init__(
        self,
        message: str,
        error_code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            message: Human-readable error message
            error_code: Machine-readable error code (e.g., "DB_CONNECTION_FAILED")
            details: Optional dictionary with additional context
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the exception."""
        if self.details:
            return f"[{self.error_code}] {self.message} | Details: {self.details}"
        return f"[{self.error_code}] {self.message}"

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for logging/API responses."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "exception_type": self.__class__.__name__,
        }


# Database and Data Storage Exceptions


class DataStoreException(AudoraException):
    """Base exception for database and data storage errors."""

    pass


class DatabaseConnectionError(DataStoreException):
    """Raised when database connection fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="DB_CONNECTION_FAILED", details=details)


class DatabaseQueryError(DataStoreException):
    """Raised when a database query fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="DB_QUERY_FAILED", details=details)


class DataValidationError(DataStoreException):
    """Raised when data fails validation before storage."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="DATA_VALIDATION_FAILED", details=details)


# External Integration Exceptions


class IntegrationException(AudoraException):
    """Base exception for external API integration errors."""

    pass


class APIConnectionError(IntegrationException):
    """Raised when connection to external API fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="API_CONNECTION_FAILED", details=details)


class APIAuthenticationError(IntegrationException):
    """Raised when API authentication fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="API_AUTH_FAILED", details=details)


class APIRateLimitError(IntegrationException):
    """Raised when API rate limit is exceeded."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="API_RATE_LIMIT_EXCEEDED", details=details)


class APIResponseError(IntegrationException):
    """Raised when API returns unexpected or invalid response."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="API_RESPONSE_INVALID", details=details)


# Analytics and Computation Exceptions


class AnalyticsException(AudoraException):
    """Base exception for analytics computation errors."""

    pass


class InsufficientDataError(AnalyticsException):
    """Raised when there is insufficient data for analysis."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="INSUFFICIENT_DATA", details=details)


class ModelTrainingError(AnalyticsException):
    """Raised when ML model training fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="MODEL_TRAINING_FAILED", details=details)


class PredictionError(AnalyticsException):
    """Raised when prediction/inference fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="PREDICTION_FAILED", details=details)


class DataProcessingError(AnalyticsException):
    """Raised when data processing/transformation fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="DATA_PROCESSING_FAILED", details=details)


# Configuration and Validation Exceptions


class ConfigurationException(AudoraException):
    """Base exception for configuration errors."""

    pass


class InvalidConfigurationError(ConfigurationException):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="INVALID_CONFIGURATION", details=details)


class MissingCredentialsError(ConfigurationException):
    """Raised when required credentials are missing."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="MISSING_CREDENTIALS", details=details)


# Notification System Exceptions


class NotificationException(AudoraException):
    """Base exception for notification system errors."""

    pass


class NotificationDeliveryError(NotificationException):
    """Raised when notification delivery fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message, error_code="NOTIFICATION_DELIVERY_FAILED", details=details
        )


class TemplateRenderError(NotificationException):
    """Raised when template rendering fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message=message, error_code="TEMPLATE_RENDER_FAILED", details=details)


# Type variables for error handling decorator
P = ParamSpec("P")
R = TypeVar("R")


def handle_errors(
    error_type: type[AudoraException], logger: logging.Logger, reraise: bool = True
) -> Callable[[Callable[P, R]], Callable[P, R | None]]:
    """Decorator for consistent error handling across the application.

    Args:
        error_type: The specific AudoraException subclass to catch
        logger: Logger instance to use for logging errors
        reraise: Whether to re-raise the exception after logging (default: True)

    Returns:
        Decorated function with error handling

    Example:
        ```python
        @handle_errors(DataStoreException, logger)
        def save_data(data: dict) -> bool:
            # Your code here
            pass
        ```
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R | None]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
            try:
                return func(*args, **kwargs)
            except error_type as e:
                logger.error(
                    f"{func.__name__} failed: {e.message}",
                    extra={
                        "error_code": e.error_code,
                        "details": e.details,
                        "function": func.__name__,
                    },
                )
                if reraise:
                    raise
                return None
            except Exception as e:
                logger.exception(f"Unexpected error in {func.__name__}: {str(e)}")
                if reraise:
                    raise error_type(
                        message=f"Unexpected error in {func.__name__}: {str(e)}",
                        error_code="UNEXPECTED_ERROR",
                        details={"original_error": str(e), "function": func.__name__},
                    ) from e
                return None

        return wrapper

    return decorator


__all__ = [
    # Base
    "AudoraException",
    # Data Store
    "DataStoreException",
    "DatabaseConnectionError",
    "DatabaseQueryError",
    "DataValidationError",
    # Integration
    "IntegrationException",
    "APIConnectionError",
    "APIAuthenticationError",
    "APIRateLimitError",
    "APIResponseError",
    # Analytics
    "AnalyticsException",
    "InsufficientDataError",
    "ModelTrainingError",
    "PredictionError",
    "DataProcessingError",
    # Configuration
    "ConfigurationException",
    "InvalidConfigurationError",
    "MissingCredentialsError",
    # Notification
    "NotificationException",
    "NotificationDeliveryError",
    "TemplateRenderError",
    # Utilities
    "handle_errors",
]
