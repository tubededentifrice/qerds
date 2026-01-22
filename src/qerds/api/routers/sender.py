"""Sender API router.

Handles sender operations for creating and managing deliveries.
All endpoints require sender authentication (sender_user role).

Covers requirements: REQ-B01, REQ-B02, REQ-B03, REQ-B05, REQ-C01
See specs/implementation/35-apis.md for API design.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from qerds.api.middleware.auth import AuthenticatedUser, require_role
from qerds.api.schemas.sender import (
    ContentObjectResponse,
    ContentUploadResponse,
    CreateDeliveryRequest,
    DeliveryListResponse,
    DeliveryResponse,
    DeliverySummary,
    DepositRequest,
    DepositResponse,
    ProofListResponse,
    ProofType,
)
from qerds.db.models.base import ActorType, DeliveryState, EventType, PartyType
from qerds.db.models.deliveries import ContentObject, Delivery
from qerds.db.models.evidence import EvidenceEvent
from qerds.db.models.parties import Party
from qerds.services.evidence import compute_content_hash
from qerds.services.lifecycle import DeliveryLifecycleService

# NOTE: ObjectStoreClient needed at runtime for return type annotation used by dependency injection
from qerds.services.storage import ObjectStoreClient  # noqa: TC001

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/sender",
    tags=["sender"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
    },
)

# Dependency for requiring sender role
SenderUser = Annotated[AuthenticatedUser, Depends(require_role("sender_user"))]


# -----------------------------------------------------------------------------
# Database session dependency (placeholder - should be configured in app startup)
# -----------------------------------------------------------------------------


async def get_db_session() -> AsyncSession:
    """Get database session.

    Uses the application's async session factory.
    """
    from qerds.db import get_async_session

    async with get_async_session() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


async def get_storage_client() -> ObjectStoreClient:
    """Get the object store client.

    This should be configured during app startup and stored in app state.
    """
    from qerds.core.settings import get_settings
    from qerds.services.storage import ObjectStoreClient

    settings = get_settings()
    return ObjectStoreClient.from_settings(settings.s3)


StorageClient = Annotated["ObjectStoreClient", Depends(get_storage_client)]


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for sender namespace.

    Returns:
        Health status for the sender API subsystem.
    """
    return {"status": "healthy", "namespace": "sender"}


# -----------------------------------------------------------------------------
# Delivery Management Endpoints
# -----------------------------------------------------------------------------


@router.post(
    "/deliveries",
    response_model=DeliveryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a draft delivery",
    description="Creates a new delivery in DRAFT state. Content must be uploaded separately.",
)
async def create_delivery(
    request: CreateDeliveryRequest,
    user: SenderUser,
    db: DbSession,
) -> DeliveryResponse:
    """Create a new draft delivery.

    Creates a delivery in DRAFT state with recipient information.
    The sender is identified from the authenticated session.
    Content objects must be uploaded separately via POST /deliveries/{id}/content.

    Args:
        request: Delivery creation parameters.
        user: Authenticated sender user.
        db: Database session.

    Returns:
        Created delivery details.

    Raises:
        HTTPException: If sender party not found or validation fails.
    """
    # Get or create sender party from authenticated user
    sender_party = await _get_or_create_sender_party(db, user)

    # Get or create recipient party from request
    recipient_party = await _get_or_create_recipient_party(
        db,
        email=request.recipient.email,
        display_name=request.recipient.display_name,
    )

    # Create the delivery in DRAFT state
    delivery = Delivery(
        sender_party_id=sender_party.party_id,
        recipient_party_id=recipient_party.party_id,
        state=DeliveryState.DRAFT,
        jurisdiction_profile=request.jurisdiction_profile,
        subject=request.subject,
        message=request.message,
        delivery_metadata=request.delivery_metadata,
    )

    db.add(delivery)
    await db.commit()
    await db.refresh(delivery, ["content_objects"])

    logger.info(
        "Created draft delivery",
        extra={
            "delivery_id": str(delivery.delivery_id),
            "sender_party_id": str(sender_party.party_id),
            "recipient_party_id": str(recipient_party.party_id),
        },
    )

    return _delivery_to_response(delivery, recipient_party)


@router.get(
    "/deliveries",
    response_model=DeliveryListResponse,
    summary="List sender's deliveries",
    description="Lists all deliveries created by the authenticated sender.",
)
async def list_deliveries(
    user: SenderUser,
    db: DbSession,
    offset: Annotated[int, Query(ge=0, description="Pagination offset")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Page size")] = 20,
    state: Annotated[str | None, Query(description="Filter by state")] = None,
) -> DeliveryListResponse:
    """List deliveries created by the authenticated sender.

    Args:
        user: Authenticated sender user.
        db: Database session.
        offset: Pagination offset.
        limit: Page size (max 100).
        state: Optional state filter.

    Returns:
        Paginated list of deliveries.
    """
    # Get sender party
    sender_party = await _get_sender_party(db, user)
    if not sender_party:
        # No party = no deliveries
        return DeliveryListResponse(items=[], total=0, offset=offset, limit=limit)

    # Build base query
    base_query = select(Delivery).where(Delivery.sender_party_id == sender_party.party_id)

    # Apply state filter
    if state:
        try:
            state_enum = DeliveryState(state)
            base_query = base_query.where(Delivery.state == state_enum)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid state: {state}",
            ) from e

    # Get total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Get paginated results with recipient party info
    query = (
        base_query.options(selectinload(Delivery.recipient_party))
        .options(selectinload(Delivery.content_objects))
        .order_by(Delivery.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(query)
    deliveries = result.scalars().all()

    # Convert to summaries
    items = [
        DeliverySummary(
            delivery_id=d.delivery_id,
            state=d.state.value,
            recipient_email=d.recipient_party.email if d.recipient_party else None,
            recipient_name=d.recipient_party.display_name if d.recipient_party else None,
            subject=d.subject,
            created_at=d.created_at,
            updated_at=d.updated_at,
            content_count=len(d.content_objects),
        )
        for d in deliveries
    ]

    return DeliveryListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get(
    "/deliveries/{delivery_id}",
    response_model=DeliveryResponse,
    summary="Get delivery details",
    description="Returns full details for a specific delivery owned by the sender.",
)
async def get_delivery(
    delivery_id: UUID,
    user: SenderUser,
    db: DbSession,
) -> DeliveryResponse:
    """Get details of a specific delivery.

    Args:
        delivery_id: UUID of the delivery.
        user: Authenticated sender user.
        db: Database session.

    Returns:
        Full delivery details.

    Raises:
        HTTPException: If delivery not found or not owned by sender.
    """
    delivery = await _get_sender_delivery(db, delivery_id, user)

    # Load recipient party for response
    recipient_party = await db.get(Party, delivery.recipient_party_id)

    return _delivery_to_response(delivery, recipient_party)


# -----------------------------------------------------------------------------
# Content Upload
# -----------------------------------------------------------------------------


@router.post(
    "/deliveries/{delivery_id}/content",
    response_model=ContentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload content object",
    description="Uploads content with integrity binding and encryption at rest (REQ-E01).",
)
async def upload_content(
    delivery_id: UUID,
    user: SenderUser,
    db: DbSession,
    storage: StorageClient,
    file: Annotated[UploadFile, File(description="Content file to upload")],
    original_filename: Annotated[str, Form(description="Original filename")],
    mime_type: Annotated[str, Form(description="MIME type")],
    sha256: Annotated[str, Form(description="SHA-256 hash (hex, 64 chars)")],
) -> ContentUploadResponse:
    """Upload a content object to a delivery.

    The content is:
    1. Verified against the provided SHA-256 hash (integrity binding per REQ-B02)
    2. Encrypted with AES-256-GCM before storage (confidentiality per REQ-E01)
    3. Stored in the object store with encryption metadata

    Args:
        delivery_id: UUID of the delivery.
        user: Authenticated sender user.
        db: Database session.
        storage: Object store client.
        file: Uploaded file.
        original_filename: Original filename.
        mime_type: MIME type of the content.
        sha256: Expected SHA-256 hash (hex-encoded).

    Returns:
        Upload result with verified hash and storage key.

    Raises:
        HTTPException: If delivery not in DRAFT state or hash mismatch.
    """
    # Validate delivery exists and is in DRAFT state
    delivery = await _get_sender_delivery(db, delivery_id, user)

    if delivery.state != DeliveryState.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot upload content to delivery in {delivery.state.value} state",
        )

    # Normalize and validate SHA-256
    expected_hash = sha256.lower()
    if len(expected_hash) != 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SHA-256 hash must be 64 hex characters",
        )

    # Read and hash the uploaded content
    content = await file.read()
    computed_hash = compute_content_hash(content)

    # Verify integrity binding (REQ-B02)
    if computed_hash != expected_hash:
        logger.warning(
            "Content hash mismatch",
            extra={
                "delivery_id": str(delivery_id),
                "expected": expected_hash[:16] + "...",
                "computed": computed_hash[:16] + "...",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content hash mismatch: provided SHA-256 does not match uploaded content",
        )

    # Generate content object ID early so we can use it for encryption AAD
    import uuid as uuid_module

    content_object_id = uuid_module.uuid4()

    # Encrypt content before storage (REQ-E01)
    from qerds.db.models.base import EncryptionScheme
    from qerds.services.content_encryption import get_content_encryption_service

    try:
        encryption_service = await get_content_encryption_service()
        ciphertext, encryption_metadata = await encryption_service.encrypt_for_storage(
            content=content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )
        encryption_scheme = EncryptionScheme.AES_256_GCM
    except Exception as e:
        logger.error(
            "Content encryption failed",
            extra={
                "delivery_id": str(delivery_id),
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt content for storage",
        ) from e

    # Upload encrypted content to object store
    storage_key = f"deliveries/{delivery_id}/content/{computed_hash}.enc"

    from qerds.services.storage import Buckets

    storage.upload(
        bucket=Buckets.CONTENT,
        key=storage_key,
        data=ciphertext,
        content_type="application/octet-stream",  # Encrypted content is binary
        metadata={
            "delivery_id": str(delivery_id),
            "original_filename": original_filename,
            "original_mime_type": mime_type,
            "encrypted": "true",
        },
    )

    # Create content object record with encryption metadata
    content_object = ContentObject(
        content_object_id=content_object_id,
        delivery_id=delivery_id,
        sha256=computed_hash,
        size_bytes=len(content),  # Original size, not encrypted size
        mime_type=mime_type,
        original_filename=original_filename,
        storage_key=storage_key,
        encryption_scheme=encryption_scheme,
        encryption_metadata=encryption_metadata,
    )

    db.add(content_object)
    await db.commit()
    await db.refresh(content_object)

    logger.info(
        "Content uploaded (encrypted)",
        extra={
            "delivery_id": str(delivery_id),
            "content_object_id": str(content_object.content_object_id),
            "size_bytes": len(content),
            "encrypted_size_bytes": len(ciphertext),
            "sha256": computed_hash[:16] + "...",
        },
    )

    return ContentUploadResponse(
        content_object_id=content_object.content_object_id,
        sha256=computed_hash,
        size_bytes=len(content),
        storage_key=storage_key,
    )


# -----------------------------------------------------------------------------
# Deposit (Submit) Delivery
# -----------------------------------------------------------------------------


@router.post(
    "/deliveries/{delivery_id}/deposit",
    response_model=DepositResponse,
    summary="Deposit delivery",
    description="Transitions delivery from DRAFT to DEPOSITED, emitting EVT_DEPOSITED evidence.",
)
async def deposit_delivery(
    delivery_id: UUID,
    user: SenderUser,
    db: DbSession,
    request: DepositRequest | None = None,  # noqa: ARG001 - reserved for future use
) -> DepositResponse:
    """Deposit (submit) a delivery.

    Transitions the delivery from DRAFT to DEPOSITED state and generates
    the EVT_DEPOSITED evidence event per REQ-B01.

    The delivery must have at least one content object before deposit.

    Args:
        delivery_id: UUID of the delivery.
        user: Authenticated sender user.
        db: Database session.
        request: Optional deposit confirmation (reserved for future use).

    Returns:
        Deposit result with evidence event reference.

    Raises:
        HTTPException: If delivery not in DRAFT state or has no content.
    """
    # Get delivery with content objects
    delivery = await _get_sender_delivery(db, delivery_id, user, load_content=True)

    if delivery.state != DeliveryState.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot deposit delivery in {delivery.state.value} state",
        )

    # Require at least one content object
    if not delivery.content_objects:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delivery must have at least one content object before deposit",
        )

    # Collect content hashes for evidence
    content_hashes = [co.sha256 for co in delivery.content_objects]

    # Get sender party for actor reference
    sender_party = await db.get(Party, delivery.sender_party_id)

    # Perform state transition with evidence generation
    lifecycle_service = DeliveryLifecycleService(db)

    # Build event metadata with sender identity tracking (REQ-B05)
    event_metadata: dict[str, Any] = {
        "sender_ial_level": _get_user_ial_level(user),
        "content_count": len(content_hashes),
    }

    result = await lifecycle_service.deposit(
        delivery_id=delivery_id,
        actor_type=ActorType.SENDER,
        actor_ref=str(sender_party.party_id) if sender_party else str(user.principal_id),
        content_hashes=content_hashes,
        event_metadata=event_metadata,
    )

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.error or "Deposit failed",
        )

    await db.commit()

    logger.info(
        "Delivery deposited",
        extra={
            "delivery_id": str(delivery_id),
            "event_id": str(result.evidence_event.event_id) if result.evidence_event else None,
            "content_count": len(content_hashes),
        },
    )

    return DepositResponse(
        delivery_id=delivery_id,
        state=result.new_state.value,
        deposited_at=delivery.deposited_at or datetime.now(UTC),
        evidence_event_id=result.evidence_event.event_id if result.evidence_event else UUID(int=0),
        content_hashes=content_hashes,
    )


# -----------------------------------------------------------------------------
# Proof Retrieval
# -----------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/proofs",
    response_model=ProofListResponse,
    summary="List available proofs",
    description="Lists all proof types available for a delivery.",
)
async def list_proofs(
    delivery_id: UUID,
    user: SenderUser,
    db: DbSession,
) -> ProofListResponse:
    """List available proof types for a delivery.

    Returns information about which proofs are available based on the
    delivery's current state and recorded evidence events.

    Args:
        delivery_id: UUID of the delivery.
        user: Authenticated sender user.
        db: Database session.

    Returns:
        List of available proof types.
    """
    # Verify sender owns this delivery
    await _get_sender_delivery(db, delivery_id, user)

    # Query evidence events for this delivery
    events_query = select(EvidenceEvent).where(EvidenceEvent.delivery_id == delivery_id)
    events_result = await db.execute(events_query)
    events = events_result.scalars().all()

    # Build event type map for quick lookup
    event_map: dict[EventType, EvidenceEvent] = {e.event_type: e for e in events}

    # Define available proof types based on events
    proof_types = [
        ProofType(
            type="deposit",
            name="Proof of Deposit",
            available=EventType.EVT_DEPOSITED in event_map,
            event_type=EventType.EVT_DEPOSITED.value,
            generated_at=(
                event_map[EventType.EVT_DEPOSITED].event_time
                if EventType.EVT_DEPOSITED in event_map
                else None
            ),
        ),
        ProofType(
            type="notification",
            name="Proof of Notification",
            available=EventType.EVT_NOTIFICATION_SENT in event_map,
            event_type=EventType.EVT_NOTIFICATION_SENT.value,
            generated_at=(
                event_map[EventType.EVT_NOTIFICATION_SENT].event_time
                if EventType.EVT_NOTIFICATION_SENT in event_map
                else None
            ),
        ),
        ProofType(
            type="acceptance",
            name="Proof of Acceptance",
            available=EventType.EVT_ACCEPTED in event_map,
            event_type=EventType.EVT_ACCEPTED.value,
            generated_at=(
                event_map[EventType.EVT_ACCEPTED].event_time
                if EventType.EVT_ACCEPTED in event_map
                else None
            ),
        ),
        ProofType(
            type="refusal",
            name="Proof of Refusal",
            available=EventType.EVT_REFUSED in event_map,
            event_type=EventType.EVT_REFUSED.value,
            generated_at=(
                event_map[EventType.EVT_REFUSED].event_time
                if EventType.EVT_REFUSED in event_map
                else None
            ),
        ),
        ProofType(
            type="receipt",
            name="Proof of Receipt",
            available=EventType.EVT_RECEIVED in event_map,
            event_type=EventType.EVT_RECEIVED.value,
            generated_at=(
                event_map[EventType.EVT_RECEIVED].event_time
                if EventType.EVT_RECEIVED in event_map
                else None
            ),
        ),
        ProofType(
            type="expiry",
            name="Proof of Expiry",
            available=EventType.EVT_EXPIRED in event_map,
            event_type=EventType.EVT_EXPIRED.value,
            generated_at=(
                event_map[EventType.EVT_EXPIRED].event_time
                if EventType.EVT_EXPIRED in event_map
                else None
            ),
        ),
    ]

    return ProofListResponse(delivery_id=delivery_id, proofs=proof_types)


@router.get(
    "/deliveries/{delivery_id}/proofs/{proof_type}",
    summary="Download proof PDF",
    description="Downloads the proof document as a PDF.",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Proof PDF document",
        },
    },
)
async def download_proof(
    delivery_id: UUID,
    proof_type: str,
    user: SenderUser,
    db: DbSession,
) -> Response:
    """Download a proof document as PDF.

    Generates and returns a PDF proof document for the specified proof type.
    The proof is only available if the corresponding evidence event exists.

    Args:
        delivery_id: UUID of the delivery.
        proof_type: Type of proof (deposit, notification, acceptance, etc.).
        user: Authenticated sender user.
        db: Database session.

    Returns:
        PDF file response.

    Raises:
        HTTPException: If proof type not available or invalid.
    """
    from qerds.services.pdf import PDFGenerationError, PDFGenerator, TemplateNotFoundError

    delivery = await _get_sender_delivery(db, delivery_id, user, load_content=True)

    # Map proof types to event types
    proof_event_map = {
        "deposit": EventType.EVT_DEPOSITED,
        "notification": EventType.EVT_NOTIFICATION_SENT,
        "acceptance": EventType.EVT_ACCEPTED,
        "refusal": EventType.EVT_REFUSED,
        "receipt": EventType.EVT_RECEIVED,
        "expiry": EventType.EVT_EXPIRED,
    }

    if proof_type not in proof_event_map:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid proof type: {proof_type}. Valid types: {list(proof_event_map.keys())}",
        )

    event_type = proof_event_map[proof_type]

    # Find the evidence event
    event_query = (
        select(EvidenceEvent)
        .where(EvidenceEvent.delivery_id == delivery_id)
        .where(EvidenceEvent.event_type == event_type)
    )
    event_result = await db.execute(event_query)
    event = event_result.scalar_one_or_none()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proof of type '{proof_type}' not available for this delivery",
        )

    # Load parties for the proof document
    sender_party = await db.get(Party, delivery.sender_party_id)
    recipient_party = await db.get(Party, delivery.recipient_party_id)

    # Generate PDF proof
    try:
        generator = PDFGenerator(qualification_mode="non_qualified")

        # Build proof context
        context = {
            "delivery_id": str(delivery_id),
            "event_id": str(event.event_id),
            "event_type": event.event_type.value,
            "event_time": event.event_time.isoformat(),
            "sender_name": sender_party.display_name if sender_party else "Unknown",
            "sender_email": sender_party.email if sender_party else None,
            "recipient_name": recipient_party.display_name if recipient_party else "Unknown",
            "recipient_email": recipient_party.email if recipient_party else None,
            "subject": delivery.subject,
            "content_count": len(delivery.content_objects),
            "content_hashes": [co.sha256 for co in delivery.content_objects],
            "jurisdiction_profile": delivery.jurisdiction_profile,
            "proof_type": proof_type,
        }

        # Map proof type to template
        template_name = f"proof_{proof_type}.html"

        pdf_result = generator.render_proof(template_name, context)

        filename = f"proof_{proof_type}_{delivery_id}.pdf"
        return Response(
            content=pdf_result.content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except TemplateNotFoundError as exc:
        # Template doesn't exist yet - return a basic text response
        logger.warning(
            "Proof template not found",
            extra={"proof_type": proof_type, "delivery_id": str(delivery_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Proof PDF generation for '{proof_type}' not yet implemented",
        ) from exc
    except PDFGenerationError as e:
        logger.error(
            "PDF generation failed",
            extra={
                "proof_type": proof_type,
                "delivery_id": str(delivery_id),
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate proof PDF",
        ) from e


# -----------------------------------------------------------------------------
# Content Download for Sender
# -----------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/content/{content_object_id}",
    summary="Download content object (sender)",
    description="""
    Download a content object attached to a delivery.

    **Authorization**: Only the sender can download their own content.

    **Encryption (REQ-E01)**: Content is stored encrypted at rest. This endpoint
    decrypts the content for the authorized sender.

    Returns the decrypted content with appropriate Content-Type and
    Content-Disposition headers.
    """,
    responses={
        200: {
            "content": {"application/octet-stream": {}},
            "description": "Content file (decrypted)",
        },
        404: {"description": "Delivery or content not found"},
    },
)
async def download_sender_content(
    delivery_id: UUID,
    content_object_id: UUID,
    user: SenderUser,
    db: DbSession,
    storage: StorageClient,
) -> Response:
    """Download content for the sender (own content).

    Senders can always download their own content regardless of delivery state.

    Args:
        delivery_id: UUID of the delivery.
        content_object_id: UUID of the content object to download.
        user: Authenticated sender user.
        db: Database session.
        storage: Object store client.

    Returns:
        Decrypted content file response.

    Raises:
        HTTPException: If delivery or content not found.
    """
    # Verify sender owns this delivery and load content
    delivery = await _get_sender_delivery(db, delivery_id, user, load_content=True)

    # Find the requested content object
    content_object = None
    for co in delivery.content_objects:
        if co.content_object_id == content_object_id:
            content_object = co
            break

    if not content_object:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content object {content_object_id} not found in delivery {delivery_id}",
        )

    # Download encrypted content from object store
    from qerds.services.storage import Buckets

    try:
        encrypted_bytes = storage.download(
            bucket=Buckets.CONTENT,
            key=content_object.storage_key,
        )
    except Exception as e:
        logger.error(
            "Failed to download content from object store",
            extra={
                "delivery_id": str(delivery_id),
                "content_object_id": str(content_object_id),
                "storage_key": content_object.storage_key,
                "error": str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve content from storage",
        ) from e

    # Decrypt content if encryption metadata is present (REQ-E01)
    plaintext = encrypted_bytes
    if content_object.encryption_metadata:
        from qerds.services.content_encryption import get_content_encryption_service

        try:
            encryption_service = await get_content_encryption_service()
            plaintext = await encryption_service.decrypt_content_object(
                ciphertext=encrypted_bytes,
                encryption_metadata=content_object.encryption_metadata,
                delivery_id=delivery_id,
                content_object_id=content_object_id,
            )
        except Exception as e:
            logger.error(
                "Failed to decrypt content",
                extra={
                    "delivery_id": str(delivery_id),
                    "content_object_id": str(content_object_id),
                    "error": str(e),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt content",
            ) from e

    logger.info(
        "Sender downloaded content",
        extra={
            "delivery_id": str(delivery_id),
            "content_object_id": str(content_object_id),
            "sender_id": str(user.principal_id),
        },
    )

    # Return decrypted content with original filename
    filename = content_object.original_filename or f"content_{content_object_id}"
    return Response(
        content=plaintext,
        media_type=content_object.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


async def _get_sender_party(db: AsyncSession, user: AuthenticatedUser) -> Party | None:
    """Get the sender party for an authenticated user.

    Args:
        db: Database session.
        user: Authenticated user.

    Returns:
        Party or None if not found.
    """
    # Look up party by principal_id
    query = select(Party).where(Party.party_id == user.principal_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def _get_or_create_sender_party(db: AsyncSession, user: AuthenticatedUser) -> Party:
    """Get or create a sender party for an authenticated user.

    Args:
        db: Database session.
        user: Authenticated user.

    Returns:
        The sender Party.
    """
    party = await _get_sender_party(db, user)
    if party:
        return party

    # Create new party from user info
    display_name = user.metadata.get("display_name") or user.metadata.get("name") or "Unknown"
    email = user.metadata.get("email")

    party = Party(
        party_id=user.principal_id,
        party_type=PartyType.NATURAL_PERSON,
        display_name=display_name,
        email=email,
    )
    db.add(party)
    await db.flush()

    return party


async def _get_or_create_recipient_party(
    db: AsyncSession,
    email: str,
    display_name: str | None = None,
) -> Party:
    """Get or create a recipient party by email.

    Args:
        db: Database session.
        email: Recipient email address.
        display_name: Optional display name.

    Returns:
        The recipient Party.
    """
    # Look up by email
    query = select(Party).where(Party.email == email)
    result = await db.execute(query)
    party = result.scalar_one_or_none()

    if party:
        return party

    # Create new party
    party = Party(
        party_type=PartyType.NATURAL_PERSON,
        display_name=display_name or email,
        email=email,
    )
    db.add(party)
    await db.flush()

    return party


async def _get_sender_delivery(
    db: AsyncSession,
    delivery_id: UUID,
    user: AuthenticatedUser,
    *,
    load_content: bool = False,
) -> Delivery:
    """Get a delivery owned by the sender.

    Args:
        db: Database session.
        delivery_id: UUID of the delivery.
        user: Authenticated sender user.
        load_content: Whether to eager-load content objects.

    Returns:
        The Delivery if found and owned by sender.

    Raises:
        HTTPException: If delivery not found or not owned by sender.
    """
    # Get sender party
    sender_party = await _get_sender_party(db, user)
    if not sender_party:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery {delivery_id} not found",
        )

    # Build query
    query = select(Delivery).where(Delivery.delivery_id == delivery_id)

    if load_content:
        query = query.options(selectinload(Delivery.content_objects))

    result = await db.execute(query)
    delivery = result.scalar_one_or_none()

    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery {delivery_id} not found",
        )

    # Verify ownership
    if delivery.sender_party_id != sender_party.party_id:
        # Return 404 to avoid leaking existence information
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery {delivery_id} not found",
        )

    return delivery


def _delivery_to_response(delivery: Delivery, recipient_party: Party | None) -> DeliveryResponse:
    """Convert a Delivery model to response schema.

    Args:
        delivery: The Delivery model.
        recipient_party: The recipient Party (optional).

    Returns:
        DeliveryResponse schema.
    """
    content_objects = [
        ContentObjectResponse(
            content_object_id=co.content_object_id,
            sha256=co.sha256,
            size_bytes=co.size_bytes,
            mime_type=co.mime_type,
            original_filename=co.original_filename,
            created_at=co.created_at,
        )
        for co in (delivery.content_objects or [])
    ]

    return DeliveryResponse(
        delivery_id=delivery.delivery_id,
        state=delivery.state.value,
        sender_party_id=delivery.sender_party_id,
        recipient_party_id=delivery.recipient_party_id,
        recipient_email=recipient_party.email if recipient_party else None,
        recipient_name=recipient_party.display_name if recipient_party else None,
        subject=delivery.subject,
        message=delivery.message,
        jurisdiction_profile=delivery.jurisdiction_profile,
        acceptance_deadline_at=delivery.acceptance_deadline_at,
        created_at=delivery.created_at,
        updated_at=delivery.updated_at,
        deposited_at=delivery.deposited_at,
        notified_at=delivery.notified_at,
        available_at=delivery.available_at,
        completed_at=delivery.completed_at,
        content_objects=content_objects,
    )


def _get_user_ial_level(user: AuthenticatedUser) -> str:
    """Extract IAL level from user session metadata.

    Per REQ-B05, we track the sender's identity proofing level.

    Args:
        user: Authenticated user.

    Returns:
        IAL level string (ial1, ial2, ial3) or 'unknown'.
    """
    # Check session metadata for IAL info
    ial = user.metadata.get("ial_level")
    if ial:
        return ial

    # Infer from auth method
    if user.auth_method == "oidc":
        # FranceConnect typically provides IAL2 or IAL3
        acr = user.metadata.get("acr", "")
        if "eidas3" in acr or "substantial" in acr.lower():
            return "ial3"
        if "eidas2" in acr:
            return "ial2"
        return "ial2"  # Default for OIDC

    # Default for other auth methods
    return "ial1"
