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
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from qerds.api.i18n import get_error_message, get_language
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
        # ISO 8601 format for JavaScript countdown
        "expires_at_iso": (
            delivery.acceptance_deadline_at.isoformat() if delivery.acceptance_deadline_at else None
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
        "content_objects": [],  # Will be populated if available
    }

    # Build content objects list if available
    if hasattr(delivery, "content_objects") and delivery.content_objects:
        total_size = 0
        for content in delivery.content_objects:
            size_bytes = getattr(content, "size_bytes", 0) or 0
            total_size += size_bytes
            content_type = getattr(content, "content_type", "application/octet-stream")
            mime_class = "pdf" if content_type == "application/pdf" else "default"
            data["content_objects"].append(
                {
                    "display_name": getattr(content, "filename", None) or "Document",
                    "mime_type": content_type,
                    "mime_type_class": mime_class,
                    "size_bytes": size_bytes,
                    "size_formatted": _format_file_size(size_bytes),
                }
            )
        data["total_size_formatted"] = _format_file_size(total_size)

    # Sender info is only revealed after accept/refuse (REQ-F03)
    if sender_revealed and delivery.sender_party:
        data["sender_name"] = delivery.sender_party.display_name
        data["sender_email"] = delivery.sender_party.email
    else:
        data["sender_name"] = None
        data["sender_email"] = None

    return data


def _format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Formatted size string (e.g., "1.2 Mo").
    """
    if size_bytes < 1024:
        return f"{size_bytes} o"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} Ko"
    return f"{size_bytes / (1024 * 1024):.2f} Mo"


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
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=get_error_message("delivery_not_found", lang),
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
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("not_recipient", lang),
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
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("not_recipient", lang),
            ) from exc

        except InsufficientIALError as e:
            # IAL level too low for LRE
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("ial_insufficient", lang),
            ) from e

        except ConsentRequiredError as exc:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=get_error_message("consent_required", lang),
            ) from exc

        except DeliveryExpiredError as exc:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=get_error_message("deadline_passed", lang),
            ) from exc

        except InvalidStateError as e:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=get_error_message("invalid_state", lang),
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
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("not_recipient", lang),
            ) from exc

        except InsufficientIALError as e:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("ial_insufficient", lang),
            ) from e

        except DeliveryExpiredError as exc:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=get_error_message("deadline_passed", lang),
            ) from exc

        except InvalidStateError as e:
            lang = get_language(request)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=get_error_message("invalid_state", lang),
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
    responses={
        200: {
            "content": {"application/octet-stream": {}},
            "description": "Content file (decrypted)",
        },
        403: {"description": "Content not yet accessible (requires acceptance)"},
        404: {"description": "Delivery or content not found"},
    },
)
async def download_content(
    request: Request,
    delivery_id: UUID,
    content_index: Annotated[int, Query(ge=0, description="Content object index")] = 0,
    user: Annotated[AuthenticatedUser | None, Depends(optional_authenticated_user)] = None,
) -> Response:
    """Download delivery content (post-acceptance only).

    This endpoint enforces the critical REQ-E02 requirement:
    content access is only allowed after acceptance.

    Args:
        request: The HTTP request.
        delivery_id: UUID of the delivery.
        content_index: Index of the content object to download (default: 0).
        user: Authenticated user (optional auth for redirect).

    Returns:
        Decrypted content file response.
    """
    # Authentication wall - redirect to auth if not authenticated
    if not user:
        return RedirectResponse(
            url=f"/pickup/{delivery_id}/auth",
            status_code=status.HTTP_302_FOUND,
        )

    from qerds.core.settings import get_settings
    from qerds.db import get_async_session
    from qerds.db.models.base import ActorType
    from qerds.services.content_encryption import get_content_encryption_service
    from qerds.services.evidence import ActorIdentification, EvidenceService
    from qerds.services.storage import Buckets, ObjectStoreClient

    lang = get_language(request)

    async with get_async_session() as db_session:
        service = PickupService(db_session)

        try:
            context = await service.get_pickup_context(
                delivery_id,
                authenticated_party_id=user.principal_id,
                ial_level=_get_ial_from_user(user),
            )
            delivery = context.delivery

            # CRITICAL: Enforce post-acceptance content access (REQ-E02)
            if delivery.state != DeliveryState.ACCEPTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=get_error_message("content_after_accept_only", lang),
                )

            # Verify content objects exist
            if not delivery.content_objects:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=get_error_message("delivery_not_found", lang),
                )

            # Get the requested content object by index
            if content_index >= len(delivery.content_objects):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=get_error_message("delivery_not_found", lang),
                )
            content_object = delivery.content_objects[content_index]

            # Retrieve encrypted content from object store
            settings = get_settings()
            storage = ObjectStoreClient.from_settings(settings.s3)

            try:
                encrypted_bytes, _metadata = storage.download(
                    bucket=Buckets.CONTENT,
                    key=content_object.storage_key,
                )
            except Exception as e:
                logger.error(
                    "Failed to retrieve content from object store",
                    extra={
                        "delivery_id": str(delivery_id),
                        "content_object_id": str(content_object.content_object_id),
                        "storage_key": content_object.storage_key,
                        "error": str(e),
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=get_error_message("storage_retrieval_failed", lang),
                ) from e

            # Decrypt content if encryption metadata is present (REQ-E01)
            plaintext = encrypted_bytes
            if content_object.encryption_metadata:
                try:
                    encryption_service = await get_content_encryption_service()
                    plaintext = await encryption_service.decrypt_content_object(
                        ciphertext=encrypted_bytes,
                        encryption_metadata=content_object.encryption_metadata,
                        delivery_id=delivery_id,
                        content_object_id=content_object.content_object_id,
                    )
                except Exception as e:
                    logger.error(
                        "Failed to decrypt content",
                        extra={
                            "delivery_id": str(delivery_id),
                            "content_object_id": str(content_object.content_object_id),
                            "error": str(e),
                        },
                    )
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=get_error_message("decryption_failed", lang),
                    ) from e

            # Record EVT_CONTENT_ACCESSED evidence event (REQ-E02, REQ-H10)
            # This provides audit trail of who accessed content and when
            try:
                evidence_service = EvidenceService(db_session)
                actor = ActorIdentification(
                    actor_type=ActorType.RECIPIENT,
                    actor_ref=str(user.principal_id),
                )
                await evidence_service.record_content_access(
                    delivery_id=delivery_id,
                    actor=actor,
                    content_object_ids=[content_object.content_object_id],
                    access_type="download",
                    event_metadata={
                        "ip_address_hash": _hash_ip(_get_client_ip(request)),
                        "session_ref": str(user.session_id) if user.session_id else None,
                        "content_index": content_index,
                    },
                )
                await db_session.commit()
            except Exception as e:
                # Log but don't fail the download - evidence is important but not blocking
                logger.warning(
                    "Failed to record content access event",
                    extra={
                        "delivery_id": str(delivery_id),
                        "content_object_id": str(content_object.content_object_id),
                        "error": str(e),
                    },
                )

            logger.info(
                "Recipient downloaded content",
                extra={
                    "delivery_id": str(delivery_id),
                    "content_object_id": str(content_object.content_object_id),
                    "recipient_id": str(user.principal_id),
                    "content_index": content_index,
                },
            )

            # Return decrypted content with original filename
            filename = (
                content_object.original_filename or f"document_{content_object.content_object_id}"
            )
            return Response(
                content=plaintext,
                media_type=content_object.mime_type,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        except DeliveryNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=get_error_message("delivery_not_found", lang),
            ) from exc

        except RecipientMismatchError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=get_error_message("not_recipient", lang),
            ) from exc


def _hash_ip(ip_address: str | None) -> str | None:
    """Hash IP address for privacy-preserving audit logging.

    Args:
        ip_address: The IP address.

    Returns:
        First 16 chars of SHA-256 hash, or None if no IP.
    """
    if not ip_address:
        return None
    import hashlib

    return hashlib.sha256(ip_address.encode()).hexdigest()[:16]


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None
