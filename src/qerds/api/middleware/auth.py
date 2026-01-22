"""Authentication middleware for session and API key validation.

Covers: REQ-D02 (access control)

This module provides authentication middleware and dependencies:
- SessionAuthMiddleware: Validates session tokens from cookies/headers
- APIKeyAuthMiddleware: Validates API keys for machine clients
- get_current_user dependency: FastAPI dependency for protected routes
- Security event logging for auth events

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import hashlib
import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from starlette.responses import Response

    from qerds.db.models.session import Session
    from qerds.services.authz import Principal

logger = logging.getLogger(__name__)

# Context variable for the current authenticated user
current_user_ctx: ContextVar[AuthenticatedUser | None] = ContextVar("current_user", default=None)

# Bearer token security scheme for OpenAPI docs
bearer_scheme = HTTPBearer(auto_error=False)

# Cookie and header names for session tokens
SESSION_COOKIE_NAME = "qerds_session"
SESSION_HEADER_NAME = "X-Session-Token"
API_KEY_HEADER = "X-API-Key"


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user in the request context.

    This is the unified representation of an authenticated principal,
    regardless of whether they authenticated via session or API key.

    Attributes:
        principal_id: UUID of the authenticated entity
        principal_type: Type of principal (admin_user, api_client, party)
        session_id: Session ID if authenticated via session
        is_superuser: Whether the user has superuser privileges
        is_active: Whether the account is active
        roles: Set of role names assigned to the user
        permissions: Set of permission strings
        ip_address: Request IP address
        user_agent: Request user agent
        auth_method: How the user authenticated (session, api_key, oidc)
        metadata: Additional authentication metadata
    """

    principal_id: UUID
    principal_type: str
    session_id: UUID | None = None
    is_superuser: bool = False
    is_active: bool = True
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    ip_address: str | None = None
    user_agent: str | None = None
    auth_method: str = "session"
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        if self.is_superuser:
            return True
        return permission in self.permissions

    def has_role(self, role: str) -> bool:
        """Check if the user has a specific role."""
        return role in self.roles

    def to_principal(self) -> Principal:
        """Convert to an authz Principal for authorization checks."""
        from qerds.services.authz import ABACContext, Principal

        return Principal(
            principal_id=self.principal_id,
            principal_type=self.principal_type,
            roles=self.roles,
            explicit_permissions=self.permissions,
            abac_context=ABACContext(
                ip_address=self.ip_address,
                user_agent=self.user_agent,
            ),
            is_superuser=self.is_superuser,
            is_active=self.is_active,
        )


def get_current_user() -> AuthenticatedUser | None:
    """Get the current authenticated user from context.

    Returns:
        The authenticated user, or None if not authenticated.
    """
    return current_user_ctx.get()


def set_current_user(user: AuthenticatedUser | None) -> None:
    """Set the current authenticated user in context."""
    current_user_ctx.set(user)


class SessionAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates session tokens and sets user context.

    This middleware:
    1. Extracts session token from cookie or header
    2. Validates the token against the database
    3. Sets the authenticated user in request context
    4. Logs authentication events

    The middleware does NOT block unauthenticated requests; that is handled
    by route-level dependencies. This allows public routes to work without
    modification.
    """

    def __init__(
        self,
        app: Any,
        *,
        get_db_session: Callable[[], AsyncSession],
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            get_db_session: Callable that returns a database session.
        """
        super().__init__(app)
        self._get_db_session = get_db_session

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request and validate session if present.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response from the handler.
        """
        # Clear any previous user context
        set_current_user(None)

        # Extract session token from cookie or header
        token = self._extract_token(request)

        if token:
            try:
                user = await self._validate_and_load_user(token, request)
                if user:
                    set_current_user(user)
                    # Store in request state for easier access in routes
                    request.state.user = user
            except Exception:
                # Log but don't fail the request - let route dependencies handle auth
                logger.exception("Error validating session token")

        return await call_next(request)

    def _extract_token(self, request: Request) -> str | None:
        """Extract session token from request.

        Checks in order:
        1. Cookie (SESSION_COOKIE_NAME)
        2. Header (SESSION_HEADER_NAME)
        3. Authorization: Bearer header

        Args:
            request: The HTTP request.

        Returns:
            The token if found, None otherwise.
        """
        # Check cookie first
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if token:
            return token

        # Check custom header
        token = request.headers.get(SESSION_HEADER_NAME)
        if token:
            return token

        # Check Authorization header (Bearer token)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]

        return None

    async def _validate_and_load_user(
        self, token: str, request: Request
    ) -> AuthenticatedUser | None:
        """Validate token and load user information.

        Args:
            token: The session token.
            request: The HTTP request (for IP/user-agent).

        Returns:
            AuthenticatedUser if valid, None otherwise.
        """
        from qerds.services.session import SessionService

        db_session = self._get_db_session()
        service = SessionService(db_session)

        session = await service.validate_session(token, update_activity=True)
        if not session:
            return None

        # Load principal-specific information
        return await self._build_authenticated_user(
            session,
            request,
            auth_method="session",
        )

    async def _build_authenticated_user(
        self,
        session: Session,
        request: Request,
        auth_method: str,
    ) -> AuthenticatedUser:
        """Build AuthenticatedUser from session and principal.

        Args:
            session: The validated session.
            request: The HTTP request.
            auth_method: How the user authenticated.

        Returns:
            Populated AuthenticatedUser.
        """
        # Extract request metadata
        ip_address = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Load roles and permissions based on principal type
        roles: frozenset[str] = frozenset()
        permissions: frozenset[str] = frozenset()
        is_superuser = False
        is_active = True

        if session.admin_user_id and session.admin_user:
            admin_user = session.admin_user
            is_superuser = admin_user.is_superuser
            is_active = admin_user.is_active
            # Load roles from role bindings
            roles = await self._load_admin_roles(session.admin_user_id)

        elif session.api_client_id and session.api_client:
            api_client = session.api_client
            is_active = api_client.is_active
            # API clients get scopes as permissions
            if api_client.allowed_scopes:
                permissions = frozenset(api_client.allowed_scopes)
            roles = await self._load_client_roles(session.api_client_id)

        elif session.party_id and session.party:
            is_active = True  # Parties don't have an is_active flag
            # Party users get basic user roles
            roles = frozenset(["sender_user", "recipient_user"])

        return AuthenticatedUser(
            principal_id=session.get_principal_id(),
            principal_type=session.get_principal_type(),
            session_id=session.session_id,
            is_superuser=is_superuser,
            is_active=is_active,
            roles=roles,
            permissions=permissions,
            ip_address=ip_address,
            user_agent=user_agent,
            auth_method=auth_method,
            metadata={
                "session_created_at": session.created_at.isoformat(),
                "session_expires_at": session.expires_at.isoformat(),
            },
        )

    async def _load_admin_roles(self, admin_user_id: UUID) -> frozenset[str]:
        """Load roles for an admin user.

        Args:
            admin_user_id: The admin user ID.

        Returns:
            Set of role names.
        """
        from sqlalchemy import select

        from qerds.db.models.auth import Role, RoleBinding

        db_session = self._get_db_session()
        result = await db_session.execute(
            select(Role.name)
            .join(RoleBinding, RoleBinding.role_id == Role.role_id)
            .where(RoleBinding.admin_user_id == admin_user_id)
        )
        return frozenset(row[0] for row in result.all())

    async def _load_client_roles(self, api_client_id: UUID) -> frozenset[str]:
        """Load roles for an API client.

        Args:
            api_client_id: The API client ID.

        Returns:
            Set of role names.
        """
        from sqlalchemy import select

        from qerds.db.models.auth import Role, RoleBinding

        db_session = self._get_db_session()
        result = await db_session.execute(
            select(Role.name)
            .join(RoleBinding, RoleBinding.role_id == Role.role_id)
            .where(RoleBinding.api_client_id == api_client_id)
        )
        return frozenset(row[0] for row in result.all())

    def _get_client_ip(self, request: Request) -> str | None:
        """Extract client IP address from request.

        Handles X-Forwarded-For header for proxied requests.

        Args:
            request: The HTTP request.

        Returns:
            Client IP address or None.
        """
        # Check X-Forwarded-For header first (for proxied requests)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return None


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates API key authentication.

    API keys are used for machine-to-machine authentication.
    They are validated against the api_clients table.

    The API key is expected in the X-API-Key header.
    """

    def __init__(
        self,
        app: Any,
        *,
        get_db_session: Callable[[], AsyncSession],
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            get_db_session: Callable that returns a database session.
        """
        super().__init__(app)
        self._get_db_session = get_db_session

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        """Process the request and validate API key if present.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware/handler in the chain.

        Returns:
            The response from the handler.
        """
        # Skip if user already authenticated (e.g., via session)
        if get_current_user() is not None:
            return await call_next(request)

        # Extract API key from header
        api_key = request.headers.get(API_KEY_HEADER)

        if api_key:
            try:
                user = await self._validate_api_key(api_key, request)
                if user:
                    set_current_user(user)
                    request.state.user = user
            except Exception:
                logger.exception("Error validating API key")

        return await call_next(request)

    async def _validate_api_key(self, api_key: str, request: Request) -> AuthenticatedUser | None:
        """Validate API key and load client information.

        Args:
            api_key: The API key to validate.
            request: The HTTP request.

        Returns:
            AuthenticatedUser if valid, None otherwise.
        """
        from sqlalchemy import select, update

        from qerds.db.models.auth import ApiClient

        db_session = self._get_db_session()

        # Hash the API key for lookup
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        # Look up client by key hash
        result = await db_session.execute(
            select(ApiClient).where(ApiClient.client_secret_hash == key_hash)
        )
        client = result.scalar_one_or_none()

        if not client:
            logger.debug("API key validation failed: key not found")
            return None

        if not client.is_active:
            logger.debug("API key validation failed: client inactive")
            return None

        # Check expiry
        if client.expires_at and datetime.now(UTC) > client.expires_at:
            logger.debug("API key validation failed: client expired")
            return None

        # Check IP allowlist if configured
        client_ip = self._get_client_ip(request)
        if (
            client.allowed_ips
            and client_ip
            and not self._ip_in_allowlist(client_ip, client.allowed_ips)
        ):
            logger.warning(
                "API key validation failed: IP %s not in allowlist for client %s",
                client_ip,
                client.client_id,
            )
            return None

        # Update last_used_at
        await db_session.execute(
            update(ApiClient)
            .where(ApiClient.api_client_id == client.api_client_id)
            .values(last_used_at=datetime.now(UTC))
        )

        # Load roles
        roles = await self._load_client_roles(client.api_client_id, db_session)

        return AuthenticatedUser(
            principal_id=client.api_client_id,
            principal_type="api_client",
            session_id=None,
            is_superuser=False,
            is_active=client.is_active,
            roles=roles,
            permissions=frozenset(client.allowed_scopes or []),
            ip_address=client_ip,
            user_agent=request.headers.get("User-Agent"),
            auth_method="api_key",
            metadata={
                "client_id": client.client_id,
                "client_name": client.name,
            },
        )

    async def _load_client_roles(
        self, api_client_id: UUID, db_session: AsyncSession
    ) -> frozenset[str]:
        """Load roles for an API client."""
        from sqlalchemy import select

        from qerds.db.models.auth import Role, RoleBinding

        result = await db_session.execute(
            select(Role.name)
            .join(RoleBinding, RoleBinding.role_id == Role.role_id)
            .where(RoleBinding.api_client_id == api_client_id)
        )
        return frozenset(row[0] for row in result.all())

    def _get_client_ip(self, request: Request) -> str | None:
        """Extract client IP address from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return None

    def _ip_in_allowlist(self, ip: str, allowlist: list[str]) -> bool:
        """Check if an IP is in the allowlist (supports CIDR notation).

        Args:
            ip: The IP address to check.
            allowlist: List of allowed IPs or CIDR ranges.

        Returns:
            True if allowed, False otherwise.
        """
        import ipaddress

        try:
            client_ip = ipaddress.ip_address(ip)
            for allowed in allowlist:
                if "/" in allowed:
                    # CIDR notation
                    network = ipaddress.ip_network(allowed, strict=False)
                    if client_ip in network:
                        return True
                else:
                    # Single IP
                    if client_ip == ipaddress.ip_address(allowed):
                        return True
            return False
        except ValueError:
            logger.warning("Invalid IP address in allowlist check: %s", ip)
            return False


# ---------------------------------------------------------------------------
# FastAPI Dependencies for route-level auth
# ---------------------------------------------------------------------------


async def require_authenticated_user(
    request: Request,
    _credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ] = None,
) -> AuthenticatedUser:
    """Dependency that requires an authenticated user.

    Use this in route definitions to protect endpoints:

        @app.get("/protected")
        async def protected_route(
            user: AuthenticatedUser = Depends(require_authenticated_user)
        ):
            ...

    The _credentials parameter is used for OpenAPI documentation but the
    actual authentication is handled by the middleware and context.

    Raises:
        HTTPException: If the user is not authenticated.
    """
    user = get_current_user()

    # Also check request state in case middleware set it there
    if not user and hasattr(request.state, "user"):
        user = request.state.user

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    return user


async def require_admin_user(
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
) -> AuthenticatedUser:
    """Dependency that requires an admin user.

    Raises:
        HTTPException: If the user is not an admin.
    """
    if user.principal_type != "admin_user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


async def require_superuser(
    user: Annotated[AuthenticatedUser, Depends(require_admin_user)],
) -> AuthenticatedUser:
    """Dependency that requires a superuser.

    Raises:
        HTTPException: If the user is not a superuser.
    """
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    return user


def require_permission(permission: str) -> Callable:
    """Factory for creating permission-checking dependencies.

    Usage:
        @app.get("/deliveries")
        async def list_deliveries(
            user: AuthenticatedUser = Depends(require_permission("view_deliveries"))
        ):
            ...

    Args:
        permission: The required permission string.

    Returns:
        A FastAPI dependency function.
    """

    async def _check_permission(
        user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    ) -> AuthenticatedUser:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}",
            )
        return user

    return _check_permission


def require_role(role: str) -> Callable:
    """Factory for creating role-checking dependencies.

    Usage:
        @app.get("/admin/users")
        async def list_users(
            user: AuthenticatedUser = Depends(require_role("admin"))
        ):
            ...

    Args:
        role: The required role name.

    Returns:
        A FastAPI dependency function.
    """

    async def _check_role(
        user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    ) -> AuthenticatedUser:
        if not user.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role}",
            )
        return user

    return _check_role


async def optional_authenticated_user(
    request: Request,
) -> AuthenticatedUser | None:
    """Dependency that optionally returns the authenticated user.

    Use this for routes that work for both authenticated and anonymous users
    but may behave differently based on auth status.

    Returns:
        The authenticated user if present, None otherwise.
    """
    user = get_current_user()
    if not user and hasattr(request.state, "user"):
        user = request.state.user
    return user
