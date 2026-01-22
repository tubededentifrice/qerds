"""QERDS API middleware components.

This module provides middleware for:
- Request ID tracking for distributed tracing
- Consistent error response formatting
- Session authentication
- API key authentication
"""

from qerds.api.middleware.auth import (
    APIKeyAuthMiddleware,
    AuthenticatedUser,
    SessionAuthMiddleware,
    get_current_user,
    optional_authenticated_user,
    require_admin_user,
    require_authenticated_user,
    require_permission,
    require_role,
    require_superuser,
    set_current_user,
)
from qerds.api.middleware.errors import ErrorHandlerMiddleware
from qerds.api.middleware.request_id import RequestIDMiddleware

__all__ = [
    "APIKeyAuthMiddleware",
    "AuthenticatedUser",
    "ErrorHandlerMiddleware",
    "RequestIDMiddleware",
    "SessionAuthMiddleware",
    "get_current_user",
    "optional_authenticated_user",
    "require_admin_user",
    "require_authenticated_user",
    "require_permission",
    "require_role",
    "require_superuser",
    "set_current_user",
]
