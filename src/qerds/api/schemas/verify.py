"""Pydantic schemas for verification API endpoints.

Covers: REQ-E03 (minimal PII), REQ-F01 (third-party verification),
REQ-F03 (pre-acceptance redaction).

These schemas define the request/response models for the public verification API.
All responses minimize PII exposure and respect pre-acceptance redaction rules.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class VerificationStatus(str, Enum):
    """Verification result status."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"


class IntegrityStatus(str, Enum):
    """Content integrity verification status."""

    VERIFIED = "verified"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


class QualificationLevel(str, Enum):
    """Qualification level of the proof."""

    QUALIFIED = "qualified"
    NON_QUALIFIED = "non_qualified"


class ProofVerificationResult(BaseModel):
    """Response schema for proof verification.

    Contains the verification result for a sealed proof with minimal PII.
    Per REQ-F03, sender identity is not revealed pre-acceptance.
    Per REQ-E03, minimal PII is exposed to third-party verifiers.
    """

    model_config = ConfigDict(from_attributes=True)

    # Core verification result
    verification_status: VerificationStatus = Field(..., description="Overall verification result")
    proof_id: UUID = Field(..., description="Proof identifier that was verified")

    # Integrity status
    integrity_status: IntegrityStatus = Field(
        ..., description="Content integrity verification status"
    )
    content_hash: str | None = Field(
        None, description="SHA-256 hash of the sealed content (if verified)"
    )

    # Qualification per REQ-G02
    qualification_level: QualificationLevel = Field(
        ..., description="Qualification level of the proof"
    )
    qualification_reason: str | None = Field(
        None, description="Explanation of qualification status"
    )

    # Timestamps (always exposed for verification)
    sealed_at: datetime | None = Field(None, description="When the proof was sealed")
    event_time: datetime | None = Field(None, description="When the underlying event occurred")

    # Provider information (always exposed per REQ-F01)
    provider_id: str | None = Field(None, description="QERDS provider identifier")
    provider_name: str | None = Field(None, description="Provider display name")

    # Event type for context
    event_type: str | None = Field(None, description="Type of evidence event (e.g., evt_deposited)")

    # Signature/seal status
    signature_valid: bool | None = Field(
        None, description="Whether the cryptographic signature is valid"
    )
    timestamp_valid: bool | None = Field(None, description="Whether the timestamp token is valid")

    # Only exposed post-acceptance (per REQ-F03)
    # These fields are None when delivery is not yet accepted
    sender_name: str | None = Field(
        None,
        description="Sender display name (only after acceptance, per REQ-F03)",
    )
    sender_email: str | None = Field(
        None,
        description="Sender email (only after acceptance, per REQ-F03)",
    )

    # Error details (for invalid/not_found cases)
    error_message: str | None = Field(None, description="Human-readable error message")
    error_code: str | None = Field(None, description="Machine-readable error code")


class DeliveryStatusResult(BaseModel):
    """Response schema for delivery status verification.

    Returns minimal status information about a delivery for third-party verifiers.
    Per REQ-F03, sender identity is not revealed pre-acceptance.
    Per REQ-E03, minimal PII is exposed.
    """

    model_config = ConfigDict(from_attributes=True)

    # Delivery identification
    delivery_id: UUID = Field(..., description="Delivery identifier")
    exists: bool = Field(..., description="Whether the delivery exists")

    # Current state (always exposed)
    state: str | None = Field(
        None, description="Current delivery state (e.g., deposited, accepted)"
    )
    is_terminal: bool = Field(False, description="Whether delivery is in a terminal state")

    # Provider information (always exposed per REQ-F01)
    provider_id: str | None = Field(None, description="QERDS provider identifier")
    provider_name: str | None = Field(None, description="Provider display name")

    # Timestamps (always exposed for verification)
    created_at: datetime | None = Field(None, description="When the delivery was created")
    deposited_at: datetime | None = Field(None, description="When the delivery was deposited")
    notified_at: datetime | None = Field(None, description="When notification was sent")
    acceptance_deadline_at: datetime | None = Field(
        None, description="Acceptance deadline (15-day window per REQ-F04)"
    )
    completed_at: datetime | None = Field(None, description="When delivery reached terminal state")

    # Content metadata (no filenames, just existence/count)
    content_count: int = Field(0, description="Number of content objects attached")

    # Integrity status
    integrity_verified: bool | None = Field(
        None, description="Whether delivery integrity has been verified"
    )

    # Only exposed post-acceptance (per REQ-F03)
    is_accepted: bool = Field(False, description="Whether delivery has been accepted")
    sender_name: str | None = Field(
        None,
        description="Sender display name (only after acceptance, per REQ-F03)",
    )
    sender_email: str | None = Field(
        None,
        description="Sender email (only after acceptance, per REQ-F03)",
    )

    # Error details
    error_message: str | None = Field(None, description="Human-readable error message")
    error_code: str | None = Field(None, description="Machine-readable error code")


class VerificationBundleInfo(BaseModel):
    """Information about a verification bundle for offline verification."""

    model_config = ConfigDict(from_attributes=True)

    hash_algorithm: str = Field(..., description="Hash algorithm used")
    signature_algorithm: str = Field(..., description="Signature algorithm used")
    algorithm_suite_version: str = Field(..., description="Crypto algorithm suite version")
    policy_oid: str | None = Field(None, description="Timestamp policy OID")
    created_at: datetime | None = Field(None, description="Bundle creation time")


class ErrorResponse(BaseModel):
    """Standard error response for verification endpoints."""

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    detail: dict[str, Any] | None = Field(None, description="Additional error details")


# Type alias for token query parameter
VerificationToken = Annotated[
    str,
    Field(
        min_length=32,
        max_length=256,
        description="Verification access token",
    ),
]
