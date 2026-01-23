"""Authentication router for OIDC/FranceConnect+ integration.

Covers: REQ-B05 (sender identity verification)

This module provides authentication endpoints for FranceConnect+ OIDC:
- GET /auth/login - Redirect to FranceConnect+ for authentication
- GET /auth/callback - Handle OIDC callback and create session
- POST /auth/logout - Logout and revoke session

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from qerds.api.i18n import get_error_message, get_language
from qerds.api.middleware.auth import (
    SESSION_COOKIE_NAME,
    AuthenticatedUser,
    optional_authenticated_user,
    require_authenticated_user,
)
from qerds.services.oidc import (
    AuthFlow,
    OIDCAuthenticationError,
    OIDCAuthRequest,
    OIDCError,
    OIDCStateError,
    OIDCTokenError,
    OIDCUserInfo,
    create_franceconnect_service_from_settings,
)

if TYPE_CHECKING:
    from uuid import UUID  # Used in type annotations only

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Forbidden"},
        500: {"description": "Internal server error"},
    },
)

# In-memory storage for pending auth requests
# In production, use Redis or similar for multi-instance deployments
_pending_auth_requests: dict[str, OIDCAuthRequest] = {}


class LoginRequest(BaseModel):
    """Request body for login initiation.

    Attributes:
        flow: Authentication flow type.
        redirect_to: Where to redirect after successful auth.
    """

    flow: AuthFlow = Field(default=AuthFlow.SENDER_IDENTITY)
    redirect_to: str = Field(default="/")


class AuthStatusResponse(BaseModel):
    """Response for auth status endpoint.

    Attributes:
        authenticated: Whether the user is authenticated.
        principal_id: UUID of the authenticated principal.
        principal_type: Type of principal.
        ial_level: Identity Assurance Level if available.
        display_name: User's display name.
    """

    authenticated: bool
    principal_id: str | None = None
    principal_type: str | None = None
    ial_level: str | None = None
    display_name: str | None = None


class LogoutResponse(BaseModel):
    """Response for logout endpoint.

    Attributes:
        success: Whether logout was successful.
        redirect_url: URL to redirect to after logout.
    """

    success: bool
    redirect_url: str = "/"


@router.get("/login")
async def login(
    request: Request,
    flow: Annotated[AuthFlow, Query()] = AuthFlow.SENDER_IDENTITY,
    redirect_to: Annotated[str, Query(alias="redirect")] = "/",
) -> RedirectResponse:
    """Initiate OIDC authentication via FranceConnect+.

    Redirects the user to FranceConnect+ for authentication.
    After successful authentication, the user is redirected back
    to /auth/callback with an authorization code.

    Args:
        request: FastAPI request object.
        flow: Authentication flow type (sender, recipient, admin).
        redirect_to: Where to redirect after successful authentication.

    Returns:
        Redirect to FranceConnect+ authorization endpoint.

    Raises:
        HTTPException: If OIDC is not configured or service error.
    """
    service = create_franceconnect_service_from_settings()
    if service is None:
        logger.warning("OIDC login attempted but service not configured")
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=get_error_message("oidc_not_configured", lang),
        )

    try:
        auth_url, auth_request = await service.create_authorization_url(
            auth_flow=flow,
            client_metadata={
                "redirect_to": redirect_to,
                "ip_address": _get_client_ip(request),
            },
        )

        # Store auth request for callback validation
        _pending_auth_requests[auth_request.state] = auth_request

        logger.info(
            "Initiating OIDC login: flow=%s, ip=%s",
            flow.value,
            _get_client_ip(request),
        )

        return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)

    except OIDCError as e:
        logger.exception("OIDC login initiation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate authentication: {e}",
        ) from e


@router.get("/callback")
async def callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> RedirectResponse:
    """Handle OIDC callback from FranceConnect+.

    Exchanges the authorization code for tokens, verifies identity,
    creates a session, and redirects to the original destination.

    Args:
        request: FastAPI request object.
        code: Authorization code from FranceConnect+.
        state: State parameter for CSRF validation.
        error: Error code if authentication failed.
        error_description: Human-readable error description.

    Returns:
        Redirect to original destination with session cookie.

    Raises:
        HTTPException: If authentication or token exchange fails.
    """
    # Handle provider-side errors
    if error:
        logger.warning(
            "OIDC callback error: error=%s, description=%s",
            error,
            error_description,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_description or error,
        )

    # Retrieve stored auth request
    stored_request = _pending_auth_requests.pop(state, None)
    if stored_request is None:
        logger.warning("OIDC callback with unknown state")
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=get_error_message("auth_request_invalid", lang),
        )

    service = create_franceconnect_service_from_settings()
    if service is None:
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=get_error_message("oidc_not_configured", lang),
        )

    try:
        # Exchange code for tokens
        auth_result = await service.exchange_code(
            code=code,
            state=state,
            stored_request=stored_request,
        )

        # Verify identity and get user info
        user_info = await service.verify_identity(auth_result)

        # Create or update party and session
        session_token = await _create_authenticated_session(
            request=request,
            user_info=user_info,
            auth_flow=stored_request.auth_flow,
            provider_id=service.provider_id,
        )

        # Get redirect destination from stored metadata
        redirect_to = stored_request.client_metadata.get("redirect_to", "/")

        logger.info(
            "OIDC authentication successful: sub_hash=%s, ial=%s, flow=%s",
            _hash_for_log(user_info.sub),
            user_info.ial_level.value,
            stored_request.auth_flow.value,
        )

        # Create response with session cookie
        response = RedirectResponse(url=redirect_to, status_code=status.HTTP_302_FOUND)
        _set_session_cookie(response, session_token)

        return response

    except OIDCStateError as e:
        logger.warning("OIDC state validation failed: %s", e)
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=get_error_message("auth_request_expired", lang),
        ) from e

    except OIDCTokenError as e:
        logger.error("OIDC token exchange failed: %s", e)
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=get_error_message("auth_token_exchange_failed", lang),
        ) from e

    except OIDCAuthenticationError as e:
        logger.error("OIDC identity verification failed: %s", e)
        lang = get_language(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=get_error_message("identity_verification_failed", lang),
        ) from e

    except OIDCError as e:
        logger.exception("OIDC callback processing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication processing failed: {e}",
        ) from e


@router.post("/logout")
async def logout(
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)],
) -> LogoutResponse:
    """Logout and revoke the current session.

    Revokes the session token and optionally redirects to FranceConnect+
    logout endpoint for single logout.

    Args:
        user: Currently authenticated user (optional).

    Returns:
        LogoutResponse with success status and redirect URL.
    """
    # Get logout redirect URL from FranceConnect+ if available
    logout_redirect = "/"

    service = create_franceconnect_service_from_settings()
    if service and user and user.metadata.get("id_token"):
        try:
            logout_url = await service.create_logout_url(
                id_token_hint=user.metadata.get("id_token"),
                post_logout_redirect_uri="/",
            )
            if logout_url:
                logout_redirect = logout_url
        except OIDCError:
            # Continue with local logout if FC+ logout fails
            pass

    # Revoke session if authenticated
    if user and user.session_id:
        await _revoke_session(user.session_id)
        logger.info(
            "User logged out: principal_id=%s, session_id=%s",
            user.principal_id,
            user.session_id,
        )

    return LogoutResponse(success=True, redirect_url=logout_redirect)


@router.get("/status")
async def get_auth_status(
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)],
) -> AuthStatusResponse:
    """Get current authentication status.

    Returns information about the currently authenticated user,
    or indicates no authentication if not logged in.

    Args:
        user: Currently authenticated user (optional).

    Returns:
        AuthStatusResponse with authentication details.
    """
    if not user:
        return AuthStatusResponse(authenticated=False)

    return AuthStatusResponse(
        authenticated=True,
        principal_id=str(user.principal_id),
        principal_type=user.principal_type,
        ial_level=user.metadata.get("ial_level"),
        display_name=user.metadata.get("display_name"),
    )


@router.delete("/session")
async def delete_session(
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    response: Response,
) -> LogoutResponse:
    """Delete the current session (API-friendly logout).

    Similar to POST /logout but designed for API clients.
    Clears the session cookie and revokes the session token.

    Args:
        user: Currently authenticated user.
        response: FastAPI response object for clearing cookies.

    Returns:
        LogoutResponse with success status.
    """
    if user.session_id:
        await _revoke_session(user.session_id)

    # Clear session cookie
    response.delete_cookie(SESSION_COOKIE_NAME)

    logger.info(
        "Session deleted: principal_id=%s, session_id=%s",
        user.principal_id,
        user.session_id,
    )

    return LogoutResponse(success=True, redirect_url="/")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _hash_for_log(value: str) -> str:
    """Hash value for privacy-safe logging."""
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _set_session_cookie(response: Response, session_token: str) -> None:
    """Set the session cookie on a response.

    Uses secure cookie settings appropriate for production:
    - httponly: Prevents JavaScript access (XSS protection)
    - samesite: Prevents CSRF attacks
    - secure: Requires HTTPS (should be True in production)

    Args:
        response: FastAPI response object.
        session_token: The session token to set.
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in production with HTTPS
        max_age=86400,  # 24 hours
        path="/",
    )


async def _create_authenticated_session(
    request: Request,
    user_info: OIDCUserInfo,
    auth_flow: AuthFlow,
    provider_id: str,
) -> str:
    """Create an authenticated session for a verified user.

    This function:
    1. Finds or creates the party record
    2. Creates an identity proofing record
    3. Creates a new session

    Args:
        request: FastAPI request object.
        user_info: Verified user information from OIDC.
        auth_flow: The authentication flow type.
        provider_id: OIDC provider identifier.

    Returns:
        Session access token.
    """
    from qerds.db import get_async_session
    from qerds.db.models.base import PartyType
    from qerds.db.models.parties import Party
    from qerds.services.oidc import create_identity_proofing_record
    from qerds.services.session import DeviceInfo, SessionService

    async with get_async_session() as db_session:
        # Find or create party
        from sqlalchemy import select

        result = await db_session.execute(
            select(Party).where(
                Party.external_provider == provider_id,
                Party.external_id == user_info.sub,
            )
        )
        party = result.scalar_one_or_none()

        if not party:
            # Create new party from OIDC claims
            party = Party(
                party_type=PartyType.NATURAL_PERSON,
                display_name=user_info.display_name,
                email=user_info.email,
                external_id=user_info.sub,
                external_provider=provider_id,
                identity_data={
                    "given_name": user_info.given_name,
                    "family_name": user_info.family_name,
                    "birthdate": user_info.birthdate,
                    "gender": user_info.gender,
                },
            )
            db_session.add(party)
            await db_session.flush()
            logger.info("Created new party from OIDC: party_id=%s", party.party_id)

        # Create identity proofing record for audit trail
        proofing_id = await create_identity_proofing_record(
            db_session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id=provider_id,
        )

        # Create session
        session_service = SessionService(db_session)
        device_info = DeviceInfo(
            ip_address=_get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )

        session_token = await session_service.create_session(
            party_id=party.party_id,
            device_info=device_info,
            session_metadata={
                "auth_flow": auth_flow.value,
                "provider_id": provider_id,
                "ial_level": user_info.ial_level.value,
                "display_name": user_info.display_name,
                "proofing_id": str(proofing_id),
            },
        )

        await db_session.commit()

        return session_token.access_token


async def _revoke_session(session_id: UUID) -> None:
    """Revoke a session by ID.

    Args:
        session_id: UUID of the session to revoke.
    """
    from qerds.db import get_async_session
    from qerds.services.session import SessionService

    async with get_async_session() as db_session:
        session_service = SessionService(db_session)
        await session_service.revoke_session(session_id, reason="logout")
        await db_session.commit()
