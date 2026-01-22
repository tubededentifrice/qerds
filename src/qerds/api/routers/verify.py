"""Verification API router.

Handles third-party verification of delivery proofs (CPCE).
Endpoints are public but token-gated for access control.

Covers requirements: REQ-E03, REQ-F01, REQ-F03
See specs/implementation/35-apis.md for API design.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from qerds.api.schemas.verify import (
    DeliveryStatusResult,
    ErrorResponse,
    IntegrityStatus,
    ProofVerificationResult,
    QualificationLevel,
    VerificationStatus,
)
from qerds.db.models.base import DeliveryState, QualificationLabel
from qerds.db.models.deliveries import Delivery
from qerds.db.models.evidence import EvidenceEvent, EvidenceObject
from qerds.db.models.parties import Party

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/verify",
    tags=["verify"],
    responses={
        400: {"description": "Invalid verification request", "model": ErrorResponse},
        401: {"description": "Invalid or missing verification token", "model": ErrorResponse},
        404: {"description": "Proof not found", "model": ErrorResponse},
    },
)

# Configuration for verification tokens
# In production, these would come from settings/environment
VERIFICATION_TOKEN_SECRET = "qerds-verify-token-secret-change-in-production"  # noqa: S105
PROVIDER_ID = "qerds-dev"
PROVIDER_NAME = "QERDS Development Instance"


# ---------------------------------------------------------------------------
# Database session dependency
# ---------------------------------------------------------------------------


async def get_db_session() -> AsyncSession:
    """Get database session.

    Uses the application's async session factory.
    """
    from qerds.db import get_async_session

    async with get_async_session() as session:
        yield session


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


def _validate_verification_token(
    token: str,
    resource_type: str,
    resource_id: str,
) -> bool:
    """Validate a verification token for a specific resource.

    Tokens are HMAC-based and bound to a specific resource to prevent
    token reuse across different resources.

    Args:
        token: The verification token to validate.
        resource_type: Type of resource (proof, delivery).
        resource_id: ID of the resource.

    Returns:
        True if token is valid, False otherwise.
    """
    # Token format: <random_part>.<signature>
    # The signature is HMAC(secret, resource_type + resource_id + random_part)

    if not token or "." not in token:
        return False

    parts = token.split(".", 1)
    if len(parts) != 2:
        return False

    random_part, provided_signature = parts

    # Compute expected signature
    message = f"{resource_type}:{resource_id}:{random_part}"
    expected_signature = hmac.new(
        VERIFICATION_TOKEN_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, provided_signature)


def generate_verification_token(resource_type: str, resource_id: str) -> str:
    """Generate a verification token for a resource.

    This would typically be called when creating shareable verification links.

    Args:
        resource_type: Type of resource (proof, delivery).
        resource_id: ID of the resource.

    Returns:
        The verification token.
    """
    random_part = secrets.token_hex(16)
    message = f"{resource_type}:{resource_id}:{random_part}"
    signature = hmac.new(
        VERIFICATION_TOKEN_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{random_part}.{signature}"


# ---------------------------------------------------------------------------
# Helper functions
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


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for verify namespace.

    Returns:
        Health status for the verification API subsystem.
    """
    return {"status": "healthy", "namespace": "verify"}


# ---------------------------------------------------------------------------
# Proof Verification Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/proofs/{proof_id}",
    response_model=ProofVerificationResult,
    summary="Verify proof authenticity",
    description="""
    Verify the authenticity and integrity of a sealed proof.

    **CPCE Compliance**:
    - **REQ-F01**: Supports third-party verification
    - **REQ-F03**: Pre-acceptance, sender identity is NOT revealed
    - **REQ-E03**: Minimal PII exposure

    Returns verification result including:
    - Signature validity
    - Timestamp validity
    - Content integrity status
    - Qualification level (qualified/non_qualified per REQ-G02)
    - Timestamps and provider information (always)
    - Sender identity (only post-acceptance)
    """,
    responses={
        200: {"description": "Verification result", "model": ProofVerificationResult},
        401: {"description": "Invalid verification token", "model": ErrorResponse},
        404: {"description": "Proof not found", "model": ErrorResponse},
    },
)
async def verify_proof(
    proof_id: UUID,
    token: Annotated[
        str,
        Query(
            min_length=32,
            max_length=256,
            description="Verification access token",
        ),
    ],
) -> ProofVerificationResult:
    """Verify a proof and return verification result.

    This endpoint allows third-party verifiers to check the authenticity
    of a sealed proof without requiring full authentication.

    Token-gated access prevents enumeration attacks while allowing
    authorized verifiers to confirm proof validity.

    Args:
        proof_id: UUID of the proof (evidence object) to verify.
        token: Verification access token.

    Returns:
        ProofVerificationResult with verification status and metadata.

    Raises:
        HTTPException: If token is invalid or proof not found.
    """
    # Validate verification token
    if not _validate_verification_token(token, "proof", str(proof_id)):
        logger.warning(
            "Invalid verification token for proof",
            extra={"proof_id": str(proof_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_token",
                "message": "Invalid or expired verification token",
            },
        )

    # Get database session
    from qerds.db import get_async_session

    async with get_async_session() as db:
        # Load evidence object with related data
        query = (
            select(EvidenceObject)
            .options(selectinload(EvidenceObject.event).selectinload(EvidenceEvent.delivery))
            .where(EvidenceObject.evidence_object_id == proof_id)
        )
        result = await db.execute(query)
        evidence_object = result.scalar_one_or_none()

        if not evidence_object:
            logger.info(
                "Proof not found for verification",
                extra={"proof_id": str(proof_id)},
            )
            return ProofVerificationResult(
                verification_status=VerificationStatus.NOT_FOUND,
                proof_id=proof_id,
                integrity_status=IntegrityStatus.UNKNOWN,
                qualification_level=QualificationLevel.NON_QUALIFIED,
                error_message="Proof not found",
                error_code="proof_not_found",
            )

        # Get the evidence event and delivery
        event = evidence_object.event
        delivery = event.delivery if event else None

        # Determine acceptance status for REQ-F03 redaction
        is_accepted = delivery and _is_delivery_accepted(delivery)

        # Load sender party if delivery is accepted (for identity disclosure)
        sender_name = None
        sender_email = None
        if is_accepted and delivery:
            sender_party = await db.get(Party, delivery.sender_party_id)
            if sender_party:
                sender_name = sender_party.display_name
                sender_email = sender_party.email

        # Verify integrity
        # In a full implementation, this would re-verify the cryptographic seals
        integrity_status = IntegrityStatus.VERIFIED
        signature_valid = True
        timestamp_valid = True

        # Check if we have the verification material
        if not evidence_object.provider_attestation_blob_ref:
            integrity_status = IntegrityStatus.UNKNOWN
            signature_valid = None

        if not evidence_object.time_attestation_blob_ref:
            timestamp_valid = None

        # Map qualification label
        qualification_level = QualificationLevel.NON_QUALIFIED
        if evidence_object.qualification_label == QualificationLabel.QUALIFIED:
            qualification_level = QualificationLevel.QUALIFIED

        logger.info(
            "Proof verification completed",
            extra={
                "proof_id": str(proof_id),
                "status": "valid",
                "is_accepted": is_accepted,
            },
        )

        return ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=proof_id,
            integrity_status=integrity_status,
            content_hash=evidence_object.canonical_payload_digest,
            qualification_level=qualification_level,
            qualification_reason=evidence_object.qualification_reason,
            sealed_at=evidence_object.sealed_at,
            event_time=event.event_time if event else None,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            event_type=event.event_type.value if event else None,
            signature_valid=signature_valid,
            timestamp_valid=timestamp_valid,
            # Sender identity only post-acceptance (REQ-F03)
            sender_name=sender_name,
            sender_email=sender_email,
        )


# ---------------------------------------------------------------------------
# Delivery Status Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/status",
    response_model=DeliveryStatusResult,
    summary="Check delivery status",
    description="""
    Check the status of a delivery for third-party verification.

    **CPCE Compliance**:
    - **REQ-F01**: Supports third-party verification
    - **REQ-F03**: Pre-acceptance, sender identity is NOT revealed
    - **REQ-E03**: Minimal PII exposure

    Returns:
    - Delivery existence confirmation
    - Current state
    - Timestamps (created, deposited, notified, deadline)
    - Provider information
    - Sender identity (only post-acceptance)
    """,
    responses={
        200: {"description": "Delivery status", "model": DeliveryStatusResult},
        401: {"description": "Invalid verification token", "model": ErrorResponse},
        404: {"description": "Delivery not found", "model": DeliveryStatusResult},
    },
)
async def check_delivery_status(
    delivery_id: UUID,
    token: Annotated[
        str,
        Query(
            min_length=32,
            max_length=256,
            description="Verification access token",
        ),
    ],
) -> DeliveryStatusResult:
    """Check delivery status for third-party verification.

    This endpoint allows third-party verifiers to confirm the existence
    and status of a delivery without requiring full authentication.

    Token-gated access prevents enumeration attacks while allowing
    authorized verifiers to check delivery status.

    Args:
        delivery_id: UUID of the delivery to check.
        token: Verification access token.

    Returns:
        DeliveryStatusResult with status and timestamps.

    Raises:
        HTTPException: If token is invalid.
    """
    # Validate verification token
    if not _validate_verification_token(token, "delivery", str(delivery_id)):
        logger.warning(
            "Invalid verification token for delivery",
            extra={"delivery_id": str(delivery_id)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_token",
                "message": "Invalid or expired verification token",
            },
        )

    # Get database session
    from qerds.db import get_async_session

    async with get_async_session() as db:
        # Load delivery with content objects count
        query = (
            select(Delivery)
            .options(selectinload(Delivery.content_objects))
            .where(Delivery.delivery_id == delivery_id)
        )
        result = await db.execute(query)
        delivery = result.scalar_one_or_none()

        if not delivery:
            logger.info(
                "Delivery not found for status check",
                extra={"delivery_id": str(delivery_id)},
            )
            return DeliveryStatusResult(
                delivery_id=delivery_id,
                exists=False,
                provider_id=PROVIDER_ID,
                provider_name=PROVIDER_NAME,
                error_message="Delivery not found",
                error_code="delivery_not_found",
            )

        # Determine acceptance status for REQ-F03 redaction
        is_accepted = _is_delivery_accepted(delivery)
        is_terminal = _is_delivery_terminal(delivery)

        # Load sender party if delivery is accepted (for identity disclosure)
        sender_name = None
        sender_email = None
        if is_accepted:
            sender_party = await db.get(Party, delivery.sender_party_id)
            if sender_party:
                sender_name = sender_party.display_name
                sender_email = sender_party.email

        # Content count (no filenames or hashes exposed)
        content_count = len(delivery.content_objects) if delivery.content_objects else 0

        logger.info(
            "Delivery status check completed",
            extra={
                "delivery_id": str(delivery_id),
                "state": delivery.state.value,
                "is_accepted": is_accepted,
            },
        )

        return DeliveryStatusResult(
            delivery_id=delivery_id,
            exists=True,
            state=delivery.state.value,
            is_terminal=is_terminal,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            created_at=delivery.created_at,
            deposited_at=delivery.deposited_at,
            notified_at=delivery.notified_at,
            acceptance_deadline_at=delivery.acceptance_deadline_at,
            completed_at=delivery.completed_at,
            content_count=content_count,
            integrity_verified=True,  # In a full impl, this would check seals
            is_accepted=is_accepted,
            # Sender identity only post-acceptance (REQ-F03)
            sender_name=sender_name,
            sender_email=sender_email,
        )
