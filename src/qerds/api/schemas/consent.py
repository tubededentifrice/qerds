"""Pydantic schemas for consent API endpoints.

Covers: REQ-F06 (Consumer consent)

These schemas define the request/response models for consent management.
Consent is required for consumer recipients before they can receive
electronic registered delivery (LRE) under CPCE.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Consent states exposed via API
ConsentStateType = Literal["pending", "granted", "withdrawn"]

# Consent types exposed via API
ConsentTypeValue = Literal["fr_lre_electronic_delivery", "eidas_electronic_delivery"]


class ConsentSummary(BaseModel):
    """Summary of a consent record.

    Used in list responses and quick status checks.
    """

    model_config = ConfigDict(from_attributes=True)

    consent_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType
    consented_at: datetime | None = None
    withdrawn_at: datetime | None = None


class ConsentDetail(BaseModel):
    """Full consent record with audit information.

    Includes timestamps, actor information, and metadata
    for compliance and audit purposes.
    """

    model_config = ConfigDict(from_attributes=True)

    consent_id: UUID
    recipient_party_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType

    # Grant information
    consented_at: datetime | None = None
    consented_by: UUID | None = None

    # Withdrawal information
    withdrawn_at: datetime | None = None
    withdrawal_reason: str | None = None

    # Timestamps
    created_at: datetime
    updated_at: datetime


class GrantConsentRequest(BaseModel):
    """Request model for granting consent.

    The recipient must explicitly acknowledge the consent text
    to grant consent for electronic delivery.
    """

    # Type of consent being granted
    consent_type: ConsentTypeValue = "fr_lre_electronic_delivery"

    # Acknowledgment that consent text was read and understood
    acknowledge_consent_text: Annotated[
        bool,
        Field(
            description="Recipient confirms they have read and accept the consent terms",
        ),
    ]

    # Hash of the consent text shown to the user (for audit trail)
    consent_text_hash: Annotated[
        str | None,
        Field(
            max_length=64,
            description="SHA-256 hash of the consent text displayed to user",
        ),
    ] = None

    # Additional metadata (e.g., consent version, language)
    metadata: dict[str, Any] | None = None


class GrantConsentResponse(BaseModel):
    """Response model for successful consent grant."""

    consent_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType
    consented_at: datetime
    message: str = "Consent granted successfully"


class WithdrawConsentRequest(BaseModel):
    """Request model for withdrawing consent.

    Recipients can withdraw their consent at any time.
    An optional reason can be provided for audit purposes.
    """

    # Type of consent being withdrawn
    consent_type: ConsentTypeValue = "fr_lre_electronic_delivery"

    # Optional reason for withdrawal (for audit trail)
    reason: Annotated[
        str | None,
        Field(
            max_length=1000,
            description="Optional reason for withdrawing consent",
        ),
    ] = None


class WithdrawConsentResponse(BaseModel):
    """Response model for successful consent withdrawal."""

    consent_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType
    withdrawn_at: datetime
    message: str = "Consent withdrawn successfully"


class ConsentStatusResponse(BaseModel):
    """Response model for consent status check.

    Quick way to check if a recipient has valid consent
    without full audit details.
    """

    recipient_party_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType
    has_valid_consent: bool
    consented_at: datetime | None = None


class ConsentListResponse(BaseModel):
    """Response model for listing all consents for a recipient."""

    recipient_party_id: UUID
    consents: list[ConsentSummary]
    total: int


class ConsentEvidenceResponse(BaseModel):
    """Response model for consent evidence export.

    Returns a complete evidence bundle suitable for
    compliance audits and legal proceedings.
    """

    consent_id: UUID
    recipient_party_id: UUID
    consent_type: ConsentTypeValue
    state: ConsentStateType
    created_at: datetime
    updated_at: datetime

    # Grant evidence (if consent was ever granted)
    grant_evidence: dict[str, Any] | None = None

    # Withdrawal evidence (if consent was withdrawn)
    withdrawal_evidence: dict[str, Any] | None = None


class ConsentErrorResponse(BaseModel):
    """Error response for consent operations."""

    error: str
    message: str
    consent_type: ConsentTypeValue | None = None
    detail: dict[str, Any] | None = None
