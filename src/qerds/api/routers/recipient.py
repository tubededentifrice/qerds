"""Recipient API router.

Handles recipient portal operations for viewing and responding to deliveries.
All endpoints require recipient authentication via FranceConnect+.

Covers requirements: REQ-E02, REQ-F03, REQ-F04, REQ-F06
See specs/implementation/35-apis.md for API design.

CPCE Compliance (Critical):
- PRE-ACCEPTANCE: sender identity MUST be hidden (REQ-F03)
- POST-ACCEPTANCE: sender identity revealed
- Acceptance window enforcement (15 days, REQ-F04)
- Consumer consent verification (REQ-F06)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from qerds.api.middleware.auth import AuthenticatedUser, require_authenticated_user
from qerds.api.schemas.recipient import (
    AcceptDeliveryRequest,
    AcceptDeliveryResponse,
    ContentObjectSummary,
    DeliveryDetail,
    DeliverySummary,
    ErrorResponse,
    InboxResponse,
    ProofType,
    RefuseDeliveryRequest,
    RefuseDeliveryResponse,
)
from qerds.db.models.base import DeliveryState
from qerds.services.evidence import apply_redaction

if TYPE_CHECKING:
    from qerds.db.models.deliveries import ContentObject, Delivery
    from qerds.db.models.parties import Party

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/recipient",
    tags=["recipient"],
    responses={
        401: {"description": "Authentication required", "model": ErrorResponse},
        403: {"description": "Insufficient permissions", "model": ErrorResponse},
    },
)


# ---------------------------------------------------------------------------
# Helper functions for redaction and authorization
# ---------------------------------------------------------------------------


def _is_delivery_accepted(delivery: Delivery) -> bool:
    """Check if delivery has been accepted by recipient.

    Post-acceptance states include ACCEPTED, RECEIVED, and terminal states
    after acceptance.
    """
    accepted_states = {
        DeliveryState.ACCEPTED,
        DeliveryState.RECEIVED,
    }
    return delivery.state in accepted_states


def _is_delivery_terminal(delivery: Delivery) -> bool:
    """Check if delivery is in a terminal state."""
    terminal_states = {
        DeliveryState.ACCEPTED,
        DeliveryState.REFUSED,
        DeliveryState.RECEIVED,
        DeliveryState.EXPIRED,
    }
    return delivery.state in terminal_states


def _get_redaction_profile(delivery: Delivery) -> str:
    """Get the redaction profile for a delivery.

    Uses the delivery's jurisdiction profile to determine redaction rules.
    """
    # Map jurisdiction profiles to redaction profiles
    profile_map = {
        "fr_lre": "fr_lre_cpce",
        "eidas": "eidas_default",
    }
    return profile_map.get(delivery.jurisdiction_profile, "fr_lre_cpce")


def _build_delivery_summary(
    delivery: Delivery,
    sender_party: Party | None,
    *,
    is_accepted: bool,
) -> DeliverySummary:
    """Build a DeliverySummary with appropriate redaction.

    Pre-acceptance: sender identity is redacted per REQ-F03.
    Post-acceptance: full sender identity is disclosed.
    """
    redaction_profile = _get_redaction_profile(delivery)

    # Build base data
    sender_name = None
    sender_email = None

    if sender_party:
        sender_name = sender_party.display_name
        sender_email = sender_party.email

    # Apply redaction for pre-acceptance state
    if not is_accepted:
        data = {
            "sender_name": sender_name,
            "sender_email": sender_email,
        }
        redacted = apply_redaction(data, redaction_profile, is_accepted=False)
        sender_name = redacted.get("sender_name")
        sender_email = redacted.get("sender_email")

    return DeliverySummary(
        delivery_id=delivery.delivery_id,
        state=delivery.state.value,
        subject=delivery.subject,
        created_at=delivery.created_at,
        acceptance_deadline_at=delivery.acceptance_deadline_at,
        sender_name=sender_name,
        sender_email=sender_email,
        is_accepted=is_accepted,
    )


def _build_delivery_detail(
    delivery: Delivery,
    sender_party: Party | None,
    content_objects: list[ContentObject],
    *,
    is_accepted: bool,
) -> DeliveryDetail:
    """Build a DeliveryDetail with appropriate redaction.

    Pre-acceptance: sender identity and content filenames are redacted.
    Post-acceptance: full disclosure.
    """
    redaction_profile = _get_redaction_profile(delivery)

    # Build sender data
    sender_party_id = str(delivery.sender_party_id) if delivery.sender_party_id else None
    sender_name = sender_party.display_name if sender_party else None
    sender_email = sender_party.email if sender_party else None

    # Build content object summaries
    content_summaries = []
    for obj in content_objects:
        filename = obj.original_filename
        if not is_accepted:
            # Redact filename pre-acceptance
            data = {"original_filename": filename}
            redacted = apply_redaction(data, redaction_profile, is_accepted=False)
            filename = redacted.get("original_filename")

        content_summaries.append(
            ContentObjectSummary(
                content_object_id=obj.content_object_id,
                mime_type=obj.mime_type,
                size_bytes=obj.size_bytes,
                original_filename=filename,
                sha256=obj.sha256,
            )
        )

    # Apply redaction to sender identity pre-acceptance
    if not is_accepted:
        data = {
            "sender_party_id": sender_party_id,
            "sender_name": sender_name,
            "sender_email": sender_email,
        }
        redacted = apply_redaction(data, redaction_profile, is_accepted=False)
        sender_party_id = redacted.get("sender_party_id")
        sender_name = redacted.get("sender_name")
        sender_email = redacted.get("sender_email")

    return DeliveryDetail(
        delivery_id=delivery.delivery_id,
        state=delivery.state.value,
        jurisdiction_profile=delivery.jurisdiction_profile,
        subject=delivery.subject,
        message=delivery.message if is_accepted else None,  # Message only after acceptance
        created_at=delivery.created_at,
        deposited_at=delivery.deposited_at,
        notified_at=delivery.notified_at,
        available_at=delivery.available_at,
        completed_at=delivery.completed_at,
        acceptance_deadline_at=delivery.acceptance_deadline_at,
        sender_party_id=sender_party_id,
        sender_name=sender_name,
        sender_email=sender_email,
        content_objects=content_summaries,
        is_accepted=is_accepted,
        is_refused=delivery.state == DeliveryState.REFUSED,
        is_expired=delivery.state == DeliveryState.EXPIRED,
    )


def _check_acceptance_deadline(delivery: Delivery) -> None:
    """Check if the acceptance deadline has passed (REQ-F04).

    Raises HTTPException if the delivery has expired.
    """
    if delivery.acceptance_deadline_at and datetime.now(UTC) > delivery.acceptance_deadline_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error": "delivery_expired",
                "message": "The acceptance deadline has passed",
                "deadline": delivery.acceptance_deadline_at.isoformat(),
            },
        )


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for recipient namespace.

    Returns:
        Health status for the recipient API subsystem.
    """
    return {"status": "healthy", "namespace": "recipient"}


# ---------------------------------------------------------------------------
# Inbox and delivery listing
# ---------------------------------------------------------------------------


@router.get(
    "/inbox",
    response_model=InboxResponse,
    summary="List pending deliveries",
    description="""
    List deliveries pending recipient action.

    **CPCE Compliance (REQ-F03)**: Pre-acceptance deliveries have sender identity redacted.
    The recipient sees that a delivery exists, the subject (if jurisdiction allows),
    and the acceptance deadline, but NOT who sent it until they accept.

    Returns deliveries in states: AVAILABLE, NOTIFIED, or recent terminal states.
    """,
)
async def list_inbox(
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    include_completed: Annotated[
        bool,
        Query(description="Include recently completed deliveries"),
    ] = False,
) -> InboxResponse:
    """List deliveries for the authenticated recipient.

    This endpoint returns deliveries addressed to the authenticated user.
    Pre-acceptance deliveries have sender identity redacted per REQ-F03.
    """
    # Note: In a real implementation, this would query the database
    # For now, return an empty inbox as a placeholder
    # The full implementation requires database session injection

    logger.info(
        "Inbox listing requested",
        extra={
            "recipient_id": str(user.principal_id),
            "page": page,
            "page_size": page_size,
            "include_completed": include_completed,
        },
    )

    # Placeholder response - actual implementation needs DB session
    # include_completed will filter by state when DB query is implemented
    _ = include_completed  # Used for logging above, full DB query pending
    return InboxResponse(
        deliveries=[],
        total=0,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Delivery detail
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}",
    response_model=DeliveryDetail,
    responses={
        404: {"description": "Delivery not found", "model": ErrorResponse},
        410: {"description": "Delivery expired", "model": ErrorResponse},
    },
    summary="Get delivery details",
    description="""
    Get detailed information about a specific delivery.

    **CPCE Compliance (REQ-F03)**: Pre-acceptance, sender identity is redacted.
    After acceptance, full sender details are revealed.

    **REQ-F04**: If the acceptance deadline has passed, returns 410 Gone.
    """,
)
async def get_delivery(
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
) -> DeliveryDetail:
    """Get delivery details for the authenticated recipient.

    Pre-acceptance: sender identity is redacted.
    Post-acceptance: full disclosure.
    """
    # Note: Full implementation requires database session
    # This is a placeholder that documents the API contract

    logger.info(
        "Delivery detail requested",
        extra={
            "delivery_id": str(delivery_id),
            "recipient_id": str(user.principal_id),
        },
    )

    # For now, return 404 as we don't have DB access yet
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "not_found",
            "message": f"Delivery {delivery_id} not found",
        },
    )


# ---------------------------------------------------------------------------
# Accept delivery
# ---------------------------------------------------------------------------


@router.post(
    "/deliveries/{delivery_id}/accept",
    response_model=AcceptDeliveryResponse,
    responses={
        400: {"description": "Invalid state for acceptance", "model": ErrorResponse},
        404: {"description": "Delivery not found", "model": ErrorResponse},
        410: {"description": "Delivery expired", "model": ErrorResponse},
    },
    summary="Accept delivery",
    description="""
    Accept a delivery, unlocking full content access and revealing sender identity.

    **CPCE Compliance**:
    - **REQ-F04**: Validates acceptance deadline (15-day window)
    - **REQ-F06**: Verifies recipient consent for electronic delivery
    - Emits EVT_ACCEPTED evidence event

    After acceptance:
    - Sender identity is revealed
    - Content download is enabled
    - Delivery transitions to ACCEPTED state
    """,
)
async def accept_delivery(
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    request: AcceptDeliveryRequest,
) -> AcceptDeliveryResponse:
    """Accept a delivery.

    This action:
    1. Validates the delivery is in AVAILABLE state
    2. Checks acceptance deadline hasn't passed (REQ-F04)
    3. Verifies electronic delivery consent if required (REQ-F06)
    4. Transitions delivery to ACCEPTED state
    5. Creates EVT_ACCEPTED evidence event
    6. Returns updated delivery with sender identity revealed
    """
    logger.info(
        "Delivery accept requested",
        extra={
            "delivery_id": str(delivery_id),
            "recipient_id": str(user.principal_id),
            "confirm_consent": request.confirm_electronic_consent,
        },
    )

    # Placeholder - full implementation requires DB session and lifecycle service
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "not_found",
            "message": f"Delivery {delivery_id} not found",
        },
    )


# ---------------------------------------------------------------------------
# Refuse delivery
# ---------------------------------------------------------------------------


@router.post(
    "/deliveries/{delivery_id}/refuse",
    response_model=RefuseDeliveryResponse,
    responses={
        400: {"description": "Invalid state for refusal", "model": ErrorResponse},
        404: {"description": "Delivery not found", "model": ErrorResponse},
        410: {"description": "Delivery expired", "model": ErrorResponse},
    },
    summary="Refuse delivery",
    description="""
    Refuse a delivery. The delivery transitions to REFUSED state.

    **CPCE Compliance**:
    - **REQ-F04**: Validates acceptance deadline (15-day window)
    - Emits EVT_REFUSED evidence event

    After refusal:
    - Delivery is in terminal REFUSED state
    - Sender is notified of refusal
    - Content access is not granted
    """,
)
async def refuse_delivery(
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    request: RefuseDeliveryRequest,
) -> RefuseDeliveryResponse:
    """Refuse a delivery.

    This action:
    1. Validates the delivery is in AVAILABLE state
    2. Checks acceptance deadline hasn't passed (REQ-F04)
    3. Transitions delivery to REFUSED state
    4. Creates EVT_REFUSED evidence event with optional reason
    5. Returns confirmation of refusal
    """
    logger.info(
        "Delivery refuse requested",
        extra={
            "delivery_id": str(delivery_id),
            "recipient_id": str(user.principal_id),
            "has_reason": bool(request.reason),
        },
    )

    # Placeholder - full implementation requires DB session and lifecycle service
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "not_found",
            "message": f"Delivery {delivery_id} not found",
        },
    )


# ---------------------------------------------------------------------------
# Content download
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/content",
    responses={
        200: {
            "description": "Content file (binary)",
            "content": {"application/octet-stream": {}},
        },
        400: {"description": "Content not available (pre-acceptance)", "model": ErrorResponse},
        403: {"description": "Not authorized to access content", "model": ErrorResponse},
        404: {"description": "Delivery or content not found", "model": ErrorResponse},
        410: {"description": "Delivery expired", "model": ErrorResponse},
    },
    summary="Download delivery content",
    description="""
    Download the content attached to a delivery.

    **CPCE Compliance (REQ-E02)**: Content access is only allowed AFTER acceptance.
    Pre-acceptance requests return 400 Bad Request.

    **Encryption (REQ-E01)**: Content is stored encrypted at rest. This endpoint
    decrypts the content for authorized recipients only.

    On first download after acceptance:
    - Emits EVT_RECEIVED evidence event
    - Delivery may transition to RECEIVED state

    Returns the decrypted content with appropriate Content-Type and
    Content-Disposition headers.
    """,
)
async def download_content(
    delivery_id: UUID,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    content_object_id: Annotated[
        UUID | None,
        Query(description="Specific content object to download (optional if single file)"),
    ] = None,
) -> Response:
    """Download delivery content (post-acceptance only).

    Content access is gated per REQ-E02 - only available after acceptance.
    Content is decrypted per REQ-E01 before returning to authorized user.

    Authorization:
    - Recipient: Only after ACCEPTED or RECEIVED state
    - Sender: Always allowed (own content)
    """
    logger.info(
        "Content download requested",
        extra={
            "delivery_id": str(delivery_id),
            "recipient_id": str(user.principal_id),
            "content_object_id": str(content_object_id) if content_object_id else None,
        },
    )

    # NOTE: Full implementation requires DB session injection via Depends
    # This is a documented placeholder showing the decryption flow:
    #
    # 1. Load delivery and verify recipient is authorized
    # 2. Check delivery state allows content access (ACCEPTED or RECEIVED)
    # 3. Load content object from database
    # 4. Download encrypted content from object store
    # 5. Decrypt using ContentEncryptionService
    # 6. Return decrypted content with proper headers
    #
    # Example decryption flow:
    # ```python
    # from qerds.services.content_encryption import get_content_encryption_service
    #
    # encryption_service = await get_content_encryption_service()
    # plaintext = await encryption_service.decrypt_for_user(
    #     ciphertext=encrypted_bytes,
    #     encryption_metadata=content_object.encryption_metadata,
    #     user=user,
    #     delivery=delivery,
    # )
    # ```

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "not_found",
            "message": f"Delivery {delivery_id} not found",
        },
    )


# ---------------------------------------------------------------------------
# Proof download
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/proofs/{proof_type}",
    responses={
        200: {
            "description": "Proof PDF document",
            "content": {"application/pdf": {}},
        },
        400: {"description": "Proof not available for this state", "model": ErrorResponse},
        404: {"description": "Delivery not found", "model": ErrorResponse},
    },
    summary="Download proof document",
    description="""
    Download a proof document (PDF) for a delivery.

    Available proof types:
    - **deposit**: Proof of deposit (available after deposit)
    - **notification**: Proof of notification (available after notification)
    - **acceptance**: Proof of acceptance (available after acceptance)
    - **refusal**: Proof of refusal (available after refusal)
    - **receipt**: Proof of receipt (available after content download)
    - **expiry**: Proof of expiry (available after expiry)

    The proof includes legally relevant information with qualification status.
    """,
)
async def download_proof(
    delivery_id: UUID,
    proof_type: ProofType,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
) -> Response:
    """Download a proof PDF document.

    The proof type must be appropriate for the delivery's current state.
    For example, acceptance proof is only available after the delivery
    has been accepted.
    """
    logger.info(
        "Proof download requested",
        extra={
            "delivery_id": str(delivery_id),
            "proof_type": proof_type,
            "recipient_id": str(user.principal_id),
        },
    )

    # Placeholder - full implementation requires:
    # 1. DB session to load delivery and verify state
    # 2. PDF service to generate proof document
    # 3. Appropriate state validation for proof type

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "not_found",
            "message": f"Delivery {delivery_id} not found",
        },
    )
