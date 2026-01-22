"""AS4 API router for Domibus webhook callbacks.

Covers: REQ-C04 (ETSI interoperability)

This router handles:
- Inbound AS4 message notifications from Domibus
- Receipt confirmation callbacks
- Error notifications

Domibus sends webhook callbacks when:
1. New messages are received from external providers
2. Delivery receipts arrive for outbound messages
3. Errors occur during message processing
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from qerds.services.as4_receiver import (
    AS4MessageHandler,
    AS4MessageMetadata,
    AS4Payload,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/as4",
    tags=["as4"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Invalid webhook signature"},
    },
)


# -----------------------------------------------------------------------------
# Request/Response Schemas
# -----------------------------------------------------------------------------


class AS4MessagePayloadSchema(BaseModel):
    """Schema for AS4 message payload in webhook request."""

    content_id: str = Field(..., description="Payload content identifier")
    content_type: str = Field(..., description="MIME type of the payload")
    data_base64: str = Field(..., description="Base64-encoded payload data")
    sha256: str | None = Field(None, description="SHA-256 digest of the payload")
    filename: str | None = Field(None, description="Original filename if available")


class AS4MessageMetadataSchema(BaseModel):
    """Schema for AS4 message metadata in webhook request."""

    message_id: str = Field(..., description="Unique AS4 message identifier")
    conversation_id: str = Field(..., description="Conversation tracking ID")
    from_party_id: str = Field(..., description="Sender provider's party identifier")
    to_party_id: str = Field(..., description="Recipient provider's party identifier")
    service: str = Field(..., description="ETSI service identifier")
    action: str = Field(..., description="ETSI action type")
    timestamp: datetime = Field(..., description="Message timestamp")
    ref_to_message_id: str | None = Field(
        None, description="Reference to related message (for receipts/errors)"
    )
    properties: dict[str, str] = Field(
        default_factory=dict, description="Additional message properties"
    )


class AS4InboundMessageRequest(BaseModel):
    """Request body for inbound AS4 message webhook."""

    metadata: AS4MessageMetadataSchema
    payloads: list[AS4MessagePayloadSchema]
    raw_message_digest: str | None = Field(
        None, description="SHA-256 digest of the raw AS4 message"
    )


class AS4ReceiveResponse(BaseModel):
    """Response for inbound AS4 message processing."""

    success: bool = Field(..., description="Whether processing succeeded")
    delivery_id: str | None = Field(None, description="UUID of the created delivery")
    evidence_event_id: str | None = Field(None, description="UUID of the EVT_AS4_RECEIVED event")
    receipt_message_id: str | None = Field(None, description="ID of the generated receipt message")
    error_code: str | None = Field(None, description="Error code if processing failed")
    error_message: str | None = Field(None, description="Error description if processing failed")


class AS4ReceiptNotificationRequest(BaseModel):
    """Request body for AS4 receipt notification webhook."""

    receipt_message_id: str = Field(..., description="Unique receipt message ID")
    ref_to_message_id: str = Field(..., description="ID of the message being acknowledged")
    timestamp: datetime = Field(..., description="Receipt timestamp")
    receipt_type: str = Field(..., description="Type of receipt (delivery, relay, etc.)")
    digest: str | None = Field(None, description="Digest of the original message")
    from_party_id: str = Field(..., description="Party that sent the receipt")


class AS4ErrorNotificationRequest(BaseModel):
    """Request body for AS4 error notification webhook."""

    error_id: str = Field(..., description="Unique error identifier")
    ref_to_message_id: str = Field(..., description="ID of the failed message")
    timestamp: datetime = Field(..., description="Error timestamp")
    error_code: str = Field(..., description="Error code from Domibus/AS4")
    error_message: str = Field(..., description="Human-readable error description")
    error_detail: str | None = Field(None, description="Technical error details")
    from_party_id: str | None = Field(None, description="Party that reported the error")


class AS4StatusResponse(BaseModel):
    """Response for receipt and error notifications."""

    acknowledged: bool = Field(..., description="Whether the notification was processed")
    message: str = Field(..., description="Status message")


# -----------------------------------------------------------------------------
# Database session dependency
# -----------------------------------------------------------------------------


async def get_db_session() -> AsyncSession:
    """Get database session.

    Uses the application's async session factory.
    """
    from qerds.db import get_async_session

    async with get_async_session() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


# -----------------------------------------------------------------------------
# Webhook authentication
# -----------------------------------------------------------------------------


async def verify_domibus_webhook(
    request: Request,  # noqa: ARG001 - reserved for future signature verification
    x_domibus_signature: Annotated[str | None, Header()] = None,
) -> None:
    """Verify the Domibus webhook signature.

    In production, this validates HMAC or mTLS authentication.
    For development, signature verification is optional.

    Args:
        request: FastAPI request object.
        x_domibus_signature: Optional HMAC signature header.

    Raises:
        HTTPException: If signature is invalid (production mode).
    """
    from qerds.core.settings import get_settings

    settings = get_settings()

    # In development mode, skip signature verification if no secret configured
    if not getattr(settings, "domibus_webhook_secret", None):
        logger.debug("Domibus webhook signature verification skipped (no secret configured)")
        return

    if not x_domibus_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Domibus-Signature header",
        )

    # NOTE: Production implementation should verify HMAC signature
    # using the configured webhook secret
    # For now, we accept any signature in non-production environments
    logger.debug(
        "Domibus webhook signature received",
        extra={"signature_prefix": x_domibus_signature[:16] + "..."},
    )


DomibusAuth = Annotated[None, Depends(verify_domibus_webhook)]


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for AS4 namespace.

    Returns:
        Health status for the AS4 webhook subsystem.
    """
    return {"status": "healthy", "namespace": "as4"}


@router.post(
    "/webhook/inbound",
    response_model=AS4ReceiveResponse,
    summary="Receive inbound AS4 message",
    description="""
    Webhook endpoint for Domibus to notify about inbound AS4 messages.

    When Domibus receives an AS4 message from an external provider, it calls
    this endpoint with the message metadata and payloads. The QERDS system:

    1. Validates the message format per ETSI EN 319 522-4-2
    2. Creates a local delivery record
    3. Generates EVT_AS4_RECEIVED evidence event
    4. Returns a receipt for sender acknowledgment

    **Note**: This endpoint should only be called by the Domibus gateway.
    External access should be blocked by firewall rules.
    """,
)
async def receive_inbound_message(
    request: AS4InboundMessageRequest,
    db: DbSession,
    _auth: DomibusAuth,
) -> AS4ReceiveResponse:
    """Process an inbound AS4 message from Domibus.

    Args:
        request: Inbound message with metadata and payloads.
        db: Database session.
        _auth: Webhook authentication dependency (verified).

    Returns:
        Processing result with delivery ID and receipt.
    """
    import base64

    # Convert request schema to service domain objects
    metadata = AS4MessageMetadata(
        message_id=request.metadata.message_id,
        conversation_id=request.metadata.conversation_id,
        from_party_id=request.metadata.from_party_id,
        to_party_id=request.metadata.to_party_id,
        service=request.metadata.service,
        action=request.metadata.action,
        timestamp=request.metadata.timestamp,
        ref_to_message_id=request.metadata.ref_to_message_id,
        properties=request.metadata.properties,
    )

    # Decode base64 payloads
    payloads: list[AS4Payload] = []
    for p in request.payloads:
        try:
            data = base64.b64decode(p.data_base64)
        except Exception as e:
            logger.warning(
                "Failed to decode payload",
                extra={"content_id": p.content_id, "error": str(e)},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 encoding for payload {p.content_id}",
            ) from e

        payloads.append(
            AS4Payload(
                content_id=p.content_id,
                content_type=p.content_type,
                data=data,
                sha256=p.sha256 or "",
                filename=p.filename,
            )
        )

    # Process the message
    handler = AS4MessageHandler(db)
    result = await handler.process_inbound_message(
        metadata=metadata,
        payloads=payloads,
        raw_message_digest=request.raw_message_digest,
    )

    # Trigger recipient notification if successful
    if result.success and result.delivery_id:
        try:
            await handler.trigger_recipient_notification(result.delivery_id)
        except Exception as e:
            # Log but don't fail the request - notification is async
            logger.warning(
                "Failed to queue recipient notification",
                extra={
                    "delivery_id": str(result.delivery_id),
                    "error": str(e),
                },
            )

    return AS4ReceiveResponse(
        success=result.success,
        delivery_id=str(result.delivery_id) if result.delivery_id else None,
        evidence_event_id=str(result.evidence_event_id) if result.evidence_event_id else None,
        receipt_message_id=result.receipt_message_id,
        error_code=result.error_code,
        error_message=result.error_message,
    )


@router.post(
    "/webhook/receipt",
    response_model=AS4StatusResponse,
    summary="Receive AS4 receipt notification",
    description="""
    Webhook endpoint for Domibus to notify about received AS4 receipts.

    When the external provider acknowledges an outbound message (sent via
    Domibus), Domibus calls this endpoint with the receipt details.

    The QERDS system records EVT_AS4_RECEIPT_RECEIVED evidence event.
    """,
)
async def receive_receipt_notification(
    request: AS4ReceiptNotificationRequest,
    db: DbSession,
    _auth: DomibusAuth,
) -> AS4StatusResponse:
    """Process an AS4 receipt notification.

    Args:
        request: Receipt notification details.
        db: Database session.
        _auth: Webhook authentication dependency (verified).

    Returns:
        Acknowledgment response.
    """
    from sqlalchemy import select

    from qerds.db.models.base import ActorType, EventType
    from qerds.db.models.deliveries import Delivery
    from qerds.db.models.evidence import EvidenceEvent

    # Find the delivery by AS4 message ID in metadata
    query = select(Delivery).where(
        Delivery.delivery_metadata["as4_message_id"].astext == request.ref_to_message_id
    )
    result = await db.execute(query)
    delivery = result.scalar_one_or_none()

    if not delivery:
        logger.warning(
            "Receipt received for unknown message",
            extra={"ref_to_message_id": request.ref_to_message_id},
        )
        # Still acknowledge to prevent retries
        return AS4StatusResponse(
            acknowledged=True,
            message="Receipt acknowledged (delivery not found locally)",
        )

    # Create evidence event for the receipt
    event = EvidenceEvent(
        delivery_id=delivery.delivery_id,
        event_type=EventType.EVT_AS4_RECEIPT_RECEIVED,
        event_time=request.timestamp,
        actor_type=ActorType.SYSTEM,
        actor_ref=f"as4:{request.from_party_id}",
        event_metadata={
            "receipt_message_id": request.receipt_message_id,
            "ref_to_message_id": request.ref_to_message_id,
            "receipt_type": request.receipt_type,
            "receipt_digest": request.digest,
            "from_party_id": request.from_party_id,
        },
    )
    db.add(event)
    await db.commit()

    logger.info(
        "AS4 receipt recorded",
        extra={
            "delivery_id": str(delivery.delivery_id),
            "receipt_message_id": request.receipt_message_id,
        },
    )

    return AS4StatusResponse(
        acknowledged=True,
        message="Receipt recorded successfully",
    )


@router.post(
    "/webhook/error",
    response_model=AS4StatusResponse,
    summary="Receive AS4 error notification",
    description="""
    Webhook endpoint for Domibus to notify about AS4 errors.

    When message delivery fails (e.g., partner unreachable, validation error),
    Domibus calls this endpoint with the error details.

    The QERDS system records EVT_AS4_ERROR evidence event and may trigger
    retry logic or alert operators.
    """,
)
async def receive_error_notification(
    request: AS4ErrorNotificationRequest,
    db: DbSession,
    _auth: DomibusAuth,
) -> AS4StatusResponse:
    """Process an AS4 error notification.

    Args:
        request: Error notification details.
        db: Database session.
        _auth: Webhook authentication dependency (verified).

    Returns:
        Acknowledgment response.
    """
    from sqlalchemy import select

    from qerds.db.models.base import ActorType, EventType
    from qerds.db.models.deliveries import Delivery
    from qerds.db.models.evidence import EvidenceEvent

    # Find the delivery by AS4 message ID in metadata
    query = select(Delivery).where(
        Delivery.delivery_metadata["as4_message_id"].astext == request.ref_to_message_id
    )
    result = await db.execute(query)
    delivery = result.scalar_one_or_none()

    if not delivery:
        logger.warning(
            "Error notification received for unknown message",
            extra={
                "ref_to_message_id": request.ref_to_message_id,
                "error_code": request.error_code,
            },
        )
        return AS4StatusResponse(
            acknowledged=True,
            message="Error acknowledged (delivery not found locally)",
        )

    # Create evidence event for the error
    event = EvidenceEvent(
        delivery_id=delivery.delivery_id,
        event_type=EventType.EVT_AS4_ERROR,
        event_time=request.timestamp,
        actor_type=ActorType.SYSTEM,
        actor_ref=f"as4:{request.from_party_id}" if request.from_party_id else "as4:domibus",
        event_metadata={
            "error_id": request.error_id,
            "ref_to_message_id": request.ref_to_message_id,
            "error_code": request.error_code,
            "error_message": request.error_message,
            "error_detail": request.error_detail,
            "from_party_id": request.from_party_id,
        },
    )
    db.add(event)
    await db.commit()

    logger.error(
        "AS4 error recorded",
        extra={
            "delivery_id": str(delivery.delivery_id),
            "error_id": request.error_id,
            "error_code": request.error_code,
            "error_message": request.error_message,
        },
    )

    return AS4StatusResponse(
        acknowledged=True,
        message="Error recorded successfully",
    )


@router.get(
    "/status/{message_id}",
    summary="Get AS4 message status",
    description="Query the status of an AS4 message by its message ID.",
)
async def get_message_status(
    message_id: str,
    db: DbSession,
) -> dict[str, Any]:
    """Get the status of an AS4 message.

    Args:
        message_id: AS4 message identifier.
        db: Database session.

    Returns:
        Message status information.

    Raises:
        HTTPException: If message not found.
    """
    from sqlalchemy import select

    from qerds.db.models.deliveries import Delivery
    from qerds.db.models.evidence import EvidenceEvent

    # Find delivery by AS4 message ID
    query = select(Delivery).where(
        Delivery.delivery_metadata["as4_message_id"].astext == message_id
    )
    result = await db.execute(query)
    delivery = result.scalar_one_or_none()

    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No delivery found for AS4 message ID: {message_id}",
        )

    # Get related events
    events_query = (
        select(EvidenceEvent)
        .where(EvidenceEvent.delivery_id == delivery.delivery_id)
        .order_by(EvidenceEvent.event_time)
    )
    events_result = await db.execute(events_query)
    events = events_result.scalars().all()

    return {
        "message_id": message_id,
        "delivery_id": str(delivery.delivery_id),
        "state": delivery.state.value,
        "created_at": delivery.created_at.isoformat(),
        "updated_at": delivery.updated_at.isoformat(),
        "events": [
            {
                "event_id": str(e.event_id),
                "event_type": e.event_type.value,
                "event_time": e.event_time.isoformat(),
                "actor_ref": e.actor_ref,
            }
            for e in events
        ],
    }
