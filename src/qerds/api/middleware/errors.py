"""Error handling middleware for consistent JSON error responses.

Provides a standardized error response format across all API endpoints.
All errors are converted to a consistent JSON structure with:
- error: Error type/code
- message: Human-readable description
- detail: Optional additional information
- request_id: Correlation ID for debugging

This ensures clients can reliably parse error responses regardless
of where in the request lifecycle the error occurred.
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from qerds.api.middleware.request_id import get_request_id

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception for API errors with structured details.

    Use this exception to raise errors with consistent formatting.
    Subclass for specific error categories.
    """

    def __init__(
        self,
        error: str,
        message: str,
        status_code: int = 400,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Initialize API error.

        Args:
            error: Machine-readable error code (e.g., "validation_error").
            message: Human-readable error description.
            status_code: HTTP status code to return.
            detail: Optional additional details for debugging.
        """
        self.error = error
        self.message = message
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)


class NotFoundError(APIError):
    """Resource not found error (404)."""

    def __init__(
        self, resource: str, identifier: str, detail: dict[str, Any] | None = None
    ) -> None:
        """Initialize not found error.

        Args:
            resource: Type of resource (e.g., "delivery", "party").
            identifier: The ID that was not found.
            detail: Optional additional details.
        """
        super().__init__(
            error="not_found",
            message=f"{resource} not found: {identifier}",
            status_code=404,
            detail=detail,
        )


class ValidationAPIError(APIError):
    """Request validation error (400)."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        """Initialize validation error.

        Args:
            message: Description of what validation failed.
            detail: Optional field-level validation details.
        """
        super().__init__(
            error="validation_error",
            message=message,
            status_code=400,
            detail=detail,
        )


class AuthorizationError(APIError):
    """Authorization/permission error (403)."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        """Initialize authorization error.

        Args:
            message: Description of why access was denied.
            detail: Optional details about required permissions.
        """
        super().__init__(
            error="forbidden",
            message=message,
            status_code=403,
            detail=detail,
        )


class AuthenticationError(APIError):
    """Authentication error (401)."""

    def __init__(
        self, message: str = "Authentication required", detail: dict[str, Any] | None = None
    ) -> None:
        """Initialize authentication error.

        Args:
            message: Description of why authentication failed.
            detail: Optional additional details.
        """
        super().__init__(
            error="unauthorized",
            message=message,
            status_code=401,
            detail=detail,
        )


def build_error_response(
    error: str,
    message: str,
    status_code: int,
    detail: dict[str, Any] | None = None,
) -> JSONResponse:
    """Build a standardized error response.

    Args:
        error: Machine-readable error code.
        message: Human-readable description.
        status_code: HTTP status code.
        detail: Optional additional details.

    Returns:
        JSONResponse with consistent error structure.
    """
    body: dict[str, Any] = {
        "error": error,
        "message": message,
    }

    # Include request ID for correlation
    request_id = get_request_id()
    if request_id:
        body["request_id"] = request_id

    # Include detail if provided
    if detail:
        body["detail"] = detail

    return JSONResponse(status_code=status_code, content=body)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Middleware that catches exceptions and returns consistent JSON errors.

    Handles:
    - APIError and subclasses: Custom application errors
    - HTTPException: FastAPI's built-in HTTP errors
    - ValidationError: Pydantic validation failures
    - Generic exceptions: Unexpected errors (logged, returns 500)
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process request and handle any exceptions.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response, or an error response if an exception occurred.
        """
        try:
            return await call_next(request)
        except APIError as exc:
            # Custom API errors - use their structure directly
            return build_error_response(
                error=exc.error,
                message=exc.message,
                status_code=exc.status_code,
                detail=exc.detail,
            )
        except HTTPException as exc:
            # FastAPI HTTP exceptions
            return build_error_response(
                error="http_error",
                message=str(exc.detail),
                status_code=exc.status_code,
            )
        except ValidationError as exc:
            # Pydantic validation errors
            return build_error_response(
                error="validation_error",
                message="Request validation failed",
                status_code=422,
                detail={"errors": exc.errors()},
            )
        except Exception:
            # Unexpected errors - log and return generic 500
            logger.exception(
                "Unexpected error processing request: %s %s",
                request.method,
                request.url.path,
            )
            return build_error_response(
                error="internal_error",
                message="An internal error occurred",
                status_code=500,
            )
