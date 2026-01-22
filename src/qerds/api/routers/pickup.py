"""Recipient pickup portal router.

Handles the magic link pickup flow with authentication wall.
This router is separate from the recipient API because it handles
both unauthenticated (claim token validation) and authenticated
(accept/refuse) operations.

Covers: REQ-E02, REQ-F03, REQ-F04, REQ-F06

Flow (per specs/implementation/05-architecture.md):
1. Recipient receives email with magic link (claim token)
2. Link redirects to pickup portal (no content access yet!)
3. Recipient MUST authenticate via FranceConnect+
4. After auth (IAL_SUBSTANTIAL+ for LRE), recipient can:
   - View delivery info (sender still hidden)
   - Accept or Refuse
5. After accept/refuse, sender identity revealed
6. After accept, content download enabled

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from qerds.api.middleware.auth import AuthenticatedUser, optional_authenticated_user
from qerds.api.templates import build_template_context, get_templates
from qerds.db.models.base import DeliveryState, IALLevel
from qerds.services.pickup import (
    ClaimTokenExpiredError,
    ConsentRequiredError,
    DeliveryExpiredError,
    DeliveryNotFoundError,
    InsufficientIALError,
    InvalidStateError,
    PickupService,
    RecipientMismatchError,
)

if TYPE_CHECKING:
    from qerds.db.models.deliveries import Delivery

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/pickup",
    tags=["pickup"],
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _get_ial_from_user(user: AuthenticatedUser | None) -> IALLevel | None:
    """Extract IAL level from authenticated user metadata.

    Args:
        user: The authenticated user.

    Returns:
        IALLevel or None.
    """
    if not user:
        return None

    ial_str = user.metadata.get("ial_level")
    if not ial_str:
        return IALLevel.IAL1  # Default for authenticated users without explicit IAL

    try:
        return IALLevel(ial_str)
    except ValueError:
        return IALLevel.IAL1


def _build_delivery_view_data(
    delivery: Delivery,
    *,
    sender_revealed: bool,
) -> dict:
    """Build delivery data for template rendering.

    Applies sender redaction based on acceptance status.

    Args:
        delivery: The delivery model.
        sender_revealed: Whether sender identity should be shown.

    Returns:
        Dict suitable for template context.
    """
    data = {
        "id": str(delivery.delivery_id),
        "subject": delivery.subject,
        "deposited_at_formatted": (
            delivery.deposited_at.strftime("%d/%m/%Y %H:%M") if delivery.deposited_at else None
        ),
        "expires_at_formatted": (
            delivery.acceptance_deadline_at.strftime("%d/%m/%Y %H:%M")
            if delivery.acceptance_deadline_at
            else None
        ),
        "accepted_at_formatted": (
            delivery.completed_at.strftime("%d/%m/%Y %H:%M")
            if delivery.completed_at and delivery.state == DeliveryState.ACCEPTED
            else None
        ),
        "refused_at_formatted": (
            delivery.completed_at.strftime("%d/%m/%Y %H:%M")
            if delivery.completed_at and delivery.state == DeliveryState.REFUSED
            else None
        ),
        "state": delivery.state.value,
        "content_size": None,  # Would come from content objects
    }

    # Sender info is only revealed after accept/refuse (REQ-F03)
    if sender_revealed and delivery.sender_party:
        data["sender_name"] = delivery.sender_party.display_name
        data["sender_email"] = delivery.sender_party.email
    else:
        data["sender_name"] = None
        data["sender_email"] = None

    return data


# ---------------------------------------------------------------------------
# Pickup portal entry (magic link landing)
# ---------------------------------------------------------------------------


@router.get(
    "/{delivery_id}",
    response_class=HTMLResponse,
    summary="Pickup portal landing page",
    description="""
    Landing page for magic link from notification email.

    This is the entry point for recipients to view and respond to deliveries.
    The page behavior depends on authentication status:

    - **Unauthenticated**: Shows delivery summary with authentication prompt
    - **Authenticated**: Shows full delivery info with accept/refuse actions

    **CPCE Compliance (REQ-F03)**: Sender identity is hidden until accept/refuse.
    """,
)
async def pickup_portal(
    request: Request,
    delivery_id: UUID,
    token: Annotated[str | None, Query(description="Claim token from magic link")] = None,
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)] = None,
) -> HTMLResponse:
    """Pickup portal landing page.

    This endpoint handles the magic link from notification emails.
    It validates the claim token and shows the pickup interface.

    The authentication wall is implemented here:
    - Without auth: Shows delivery info + auth prompt
    - With auth: Shows delivery info + accept/refuse buttons
    """
    from qerds.db import get_async_session

    templates = get_templates()

    async with get_async_session() as db_session:
        service = PickupService(db_session)

        try:
            # Validate claim token if provided (entry from magic link)
            if token:
                delivery = await service.validate_claim_token(token, delivery_id)
            else:
                # No token - validate delivery exists and user has access
                context = await service.get_pickup_context(
                    delivery_id,
                    authenticated_party_id=user.principal_id if user else None,
                    ial_level=_get_ial_from_user(user),
                )
                delivery = context.delivery

        except ClaimTokenExpiredError:
            # Token expired - show error page
            ctx = build_template_context(request, error="token_expired")
            return templates.TemplateResponse("recipient/error.html", ctx)

        except DeliveryNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Delivery not found",
            ) from exc

        except DeliveryExpiredError:
            # Acceptance deadline passed
            ctx = build_template_context(
                request,
                error="expired",
                delivery=_build_delivery_view_data(delivery, sender_revealed=True),
            )
            return templates.TemplateResponse("recipient/expired.html", ctx)

        except RecipientMismatchError as exc:
            # Authenticated user is not the recipient
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not the recipient of this delivery",
            ) from exc

        # Get full pickup context with auth status
        context = await service.get_pickup_context(
            delivery_id,
            authenticated_party_id=user.principal_id if user else None,
            ial_level=_get_ial_from_user(user),
        )

        # Build template context
        delivery_data = _build_delivery_view_data(
            delivery,
            sender_revealed=context.sender_revealed,
        )

        # Route to appropriate template based on state
        if delivery.state == DeliveryState.ACCEPTED:
            template_name = "recipient/accepted.html"
        elif delivery.state == DeliveryState.REFUSED:
            template_name = "recipient/refused.html"
        elif delivery.state == DeliveryState.EXPIRED:
            template_name = "recipient/expired.html"
        else:
            template_name = "recipient/pickup.html"

        ctx = build_template_context(
            request,
            delivery=delivery_data,
            user=user,
            is_authenticated=context.is_authenticated,
            can_accept_refuse=context.can_accept_refuse,
            has_consent=context.has_consent,
            ial_level=context.ial_level.value if context.ial_level else None,
        )

        return templates.TemplateResponse(template_name, ctx)


# ---------------------------------------------------------------------------
# Recipient authentication redirect (auth wall)
# ---------------------------------------------------------------------------


@router.get(
    "/{delivery_id}/auth",
    response_class=RedirectResponse,
    summary="Start authentication for pickup",
    description="""
    Redirect to FranceConnect+ for recipient authentication.

    This is the authentication wall - recipients MUST authenticate
    before they can accept or refuse a delivery.

    After successful authentication, the user is redirected back
    to the pickup portal with a session cookie.
    """,
)
async def start_pickup_auth(
    delivery_id: UUID,
) -> RedirectResponse:
    """Start FranceConnect+ authentication for pickup.

    Redirects to /auth/login with appropriate flow and redirect target.
    """
    # Build redirect URL back to pickup portal after auth
    redirect_to = f"/pickup/{delivery_id}"

    # Redirect to auth login with recipient_pickup flow
    auth_url = f"/auth/login?flow=recipient_pickup&redirect={redirect_to}"

    logger.info(
        "Starting pickup authentication",
        extra={
            "delivery_id": str(delivery_id),
            "redirect_to": redirect_to,
        },
    )

    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------------------------
# Accept delivery
# ---------------------------------------------------------------------------


@router.post(
    "/{delivery_id}/accept",
    response_class=RedirectResponse,
    summary="Accept delivery",
    description="""
    Accept a delivery, revealing sender identity and enabling content download.

    **Requirements**:
    - Must be authenticated via FranceConnect+
    - For LRE: Must have IAL_SUBSTANTIAL (eidas2) or higher
    - For LRE consumers: Must confirm electronic delivery consent

    **After acceptance**:
    - Sender identity is revealed
    - Content download is enabled
    - Proof of acceptance is generated
    """,
)
async def accept_delivery(
    request: Request,
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)] = None,
    confirm_consent: Annotated[bool, Query()] = True,
) -> RedirectResponse:
    """Accept a delivery.

    Requires authentication. Redirects to auth if not authenticated.
    """
    # Authentication wall
    if not user:
        return RedirectResponse(
            url=f"/pickup/{delivery_id}/auth",
            status_code=status.HTTP_302_FOUND,
        )

    from qerds.db import get_async_session

    async with get_async_session() as db_session:
        service = PickupService(db_session)
        ial_level = _get_ial_from_user(user)

        try:
            await service.accept_delivery(
                delivery_id,
                recipient_party_id=user.principal_id,
                ial_level=ial_level or IALLevel.IAL1,
                confirm_consent=confirm_consent,
                session_ref=str(user.session_id) if user.session_id else None,
                ip_address=_get_client_ip(request),
            )
            await db_session.commit()

            logger.info(
                "Delivery accepted via pickup portal",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_id": str(user.principal_id),
                    "ial_level": ial_level.value if ial_level else None,
                },
            )

            # Redirect to accepted page
            return RedirectResponse(
                url=f"/pickup/{delivery_id}",
                status_code=status.HTTP_302_FOUND,
            )

        except RecipientMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not the recipient of this delivery",
            ) from exc

        except InsufficientIALError as e:
            # IAL level too low for LRE
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Identity assurance level {e.actual.value} is insufficient. "
                f"LRE requires at least {e.required.value}. "
                "Please re-authenticate with FranceConnect+.",
            ) from e

        except ConsentRequiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Electronic delivery consent is required for LRE recipients",
            ) from exc

        except DeliveryExpiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="The acceptance deadline has passed",
            ) from exc

        except InvalidStateError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot accept delivery in state {e.current_state.value}",
            ) from e


# ---------------------------------------------------------------------------
# Refuse delivery
# ---------------------------------------------------------------------------


@router.post(
    "/{delivery_id}/refuse",
    response_class=RedirectResponse,
    summary="Refuse delivery",
    description="""
    Refuse a delivery. Content remains inaccessible.

    **Requirements**:
    - Must be authenticated via FranceConnect+
    - For LRE: Must have IAL_SUBSTANTIAL (eidas2) or higher

    **After refusal**:
    - Sender identity is revealed
    - Content download remains disabled
    - Proof of refusal is generated
    - Sender is notified
    """,
)
async def refuse_delivery(
    request: Request,
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)] = None,
    reason: Annotated[str | None, Query(description="Optional reason for refusal")] = None,
) -> RedirectResponse:
    """Refuse a delivery.

    Requires authentication. Redirects to auth if not authenticated.
    """
    # Authentication wall
    if not user:
        return RedirectResponse(
            url=f"/pickup/{delivery_id}/auth",
            status_code=status.HTTP_302_FOUND,
        )

    from qerds.db import get_async_session

    async with get_async_session() as db_session:
        service = PickupService(db_session)
        ial_level = _get_ial_from_user(user)

        try:
            await service.refuse_delivery(
                delivery_id,
                recipient_party_id=user.principal_id,
                ial_level=ial_level or IALLevel.IAL1,
                reason=reason,
                session_ref=str(user.session_id) if user.session_id else None,
                ip_address=_get_client_ip(request),
            )
            await db_session.commit()

            logger.info(
                "Delivery refused via pickup portal",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_id": str(user.principal_id),
                    "has_reason": bool(reason),
                },
            )

            # Redirect to refused page
            return RedirectResponse(
                url=f"/pickup/{delivery_id}",
                status_code=status.HTTP_302_FOUND,
            )

        except RecipientMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not the recipient of this delivery",
            ) from exc

        except InsufficientIALError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Identity assurance level {e.actual.value} is insufficient. "
                f"LRE requires at least {e.required.value}. "
                "Please re-authenticate with FranceConnect+.",
            ) from e

        except DeliveryExpiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="The acceptance deadline has passed",
            ) from exc

        except InvalidStateError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot refuse delivery in state {e.current_state.value}",
            ) from e


# ---------------------------------------------------------------------------
# Content download (post-acceptance only)
# ---------------------------------------------------------------------------


@router.get(
    "/{delivery_id}/content",
    summary="Download delivery content",
    description="""
    Download the content attached to a delivery.

    **CRITICAL (REQ-E02)**: Content access is ONLY allowed AFTER acceptance.
    Attempting to download before acceptance returns 403 Forbidden.

    On first download:
    - EVT_CONTENT_ACCESSED evidence event is recorded
    - Delivery may transition to RECEIVED state
    """,
)
async def download_content(
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)] = None,
) -> RedirectResponse:
    """Download delivery content (post-acceptance only).

    This endpoint enforces the critical REQ-E02 requirement:
    content access is only allowed after acceptance.
    """
    # Authentication wall
    if not user:
        return RedirectResponse(
            url=f"/pickup/{delivery_id}/auth",
            status_code=status.HTTP_302_FOUND,
        )

    from qerds.db import get_async_session

    async with get_async_session() as db_session:
        service = PickupService(db_session)

        try:
            context = await service.get_pickup_context(
                delivery_id,
                authenticated_party_id=user.principal_id,
                ial_level=_get_ial_from_user(user),
            )

            # CRITICAL: Enforce post-acceptance content access (REQ-E02)
            if context.delivery.state != DeliveryState.ACCEPTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Content download is only available after accepting the delivery",
                )

            # TODO: Implement actual content retrieval from object store
            # For now, return a placeholder response
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Content download not yet implemented",
            )

        except DeliveryNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Delivery not found",
            ) from exc

        except RecipientMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not the recipient of this delivery",
            ) from exc


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None
