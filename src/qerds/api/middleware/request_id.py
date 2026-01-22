"""Request ID middleware for distributed tracing.

Adds X-Request-ID header to all responses for request correlation.
If the client provides a request ID, it is used; otherwise, a new UUID is generated.

This enables:
- Correlating logs across services
- Debugging request flows
- Audit trail linking
"""

import uuid
from collections.abc import Callable
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Context variable for accessing request ID in the current request context
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

# Header name for request ID (industry standard)
REQUEST_ID_HEADER = "X-Request-ID"


def get_request_id() -> str | None:
    """Get the current request ID from context.

    Returns:
        The request ID for the current request, or None if not in a request context.
    """
    return request_id_ctx.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware that ensures every request has a unique X-Request-ID.

    If the incoming request has an X-Request-ID header, it is preserved.
    Otherwise, a new UUID v4 is generated. The request ID is:
    - Stored in a context variable for access in handlers
    - Added to the response headers for client correlation
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request and add X-Request-ID to response.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response with X-Request-ID header added.
        """
        # Use existing request ID or generate a new one
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())

        # Store in context for use in handlers and logging
        request_id_ctx.set(request_id)

        # Process the request
        response = await call_next(request)

        # Add request ID to response headers
        response.headers[REQUEST_ID_HEADER] = request_id

        return response
