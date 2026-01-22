"""Pydantic schemas for recipient API endpoints.

Covers: REQ-E02 (content access), REQ-F03 (pre-acceptance redaction),
        REQ-F04 (acceptance window)

These schemas define the request/response models for the recipient portal API.
Pre-acceptance redaction is applied at the response level - sender identity
fields are set to "[REDACTED]" for deliveries not yet accepted (REQ-F03).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ContentObjectSummary(BaseModel):
    """Summary of a content object for display (may be redacted pre-acceptance).

    Pre-acceptance: filename and content_description are redacted per REQ-F03.
    Post-acceptance: full metadata is visible.
    """

    model_config = ConfigDict(from_attributes=True)

    content_object_id: UUID
    mime_type: str
    size_bytes: int
    # These fields are redacted pre-acceptance (REQ-F03)
    original_filename: str | None = None
    sha256: str  # Always visible for integrity verification


class DeliverySummary(BaseModel):
    """Summary of a delivery for inbox listing.

    Pre-acceptance (REQ-F03): sender identity is redacted.
    The recipient sees that a delivery exists, its subject (if allowed),
    and the acceptance deadline, but not who sent it.
    """

    model_config = ConfigDict(from_attributes=True)

    delivery_id: UUID
    state: str
    # Subject may or may not be redacted depending on jurisdiction profile
    subject: str | None = None
    created_at: datetime
    acceptance_deadline_at: datetime | None = None
    # Sender identity fields - redacted pre-acceptance per REQ-F03
    sender_name: str | None = None
    sender_email: str | None = None
    # Indicates whether full details are available (post-acceptance)
    is_accepted: bool = False


class DeliveryDetail(BaseModel):
    """Full delivery detail for recipient view.

    Pre-acceptance: sender identity fields are redacted.
    Post-acceptance: full disclosure of sender identity.

    This is the response model for GET /recipient/deliveries/{id}.
    """

    model_config = ConfigDict(from_attributes=True)

    delivery_id: UUID
    state: str
    jurisdiction_profile: str
    subject: str | None = None
    message: str | None = None
    created_at: datetime
    deposited_at: datetime | None = None
    notified_at: datetime | None = None
    available_at: datetime | None = None
    completed_at: datetime | None = None
    acceptance_deadline_at: datetime | None = None

    # Sender identity - redacted pre-acceptance per REQ-F03
    sender_party_id: str | None = None  # UUID as string or "[REDACTED]"
    sender_name: str | None = None
    sender_email: str | None = None

    # Content objects (filenames may be redacted pre-acceptance)
    content_objects: list[ContentObjectSummary] = Field(default_factory=list)

    # Acceptance status
    is_accepted: bool = False
    is_refused: bool = False
    is_expired: bool = False


class InboxResponse(BaseModel):
    """Response model for GET /recipient/inbox.

    Contains paginated list of deliveries pending recipient action.
    """

    deliveries: list[DeliverySummary]
    total: int
    page: int = 1
    page_size: int = 20


class AcceptDeliveryRequest(BaseModel):
    """Request model for POST /recipient/deliveries/{id}/accept.

    The accept action requires minimal input - the recipient's identity
    is determined from their authentication session.
    """

    # Optional confirmation of consent to receive electronic delivery (REQ-F06)
    confirm_electronic_consent: bool = True


class AcceptDeliveryResponse(BaseModel):
    """Response model for POST /recipient/deliveries/{id}/accept.

    Returns the updated delivery state and confirmation of acceptance.
    """

    delivery_id: UUID
    state: str
    accepted_at: datetime
    # Now that delivery is accepted, sender identity is revealed
    sender_name: str | None = None
    sender_email: str | None = None
    # Content is now accessible
    content_available: bool = True


class RefuseDeliveryRequest(BaseModel):
    """Request model for POST /recipient/deliveries/{id}/refuse.

    The recipient may optionally provide a refusal reason.
    """

    # Optional reason for refusal (stored in evidence but not required)
    reason: Annotated[str | None, Field(max_length=1000)] = None


class RefuseDeliveryResponse(BaseModel):
    """Response model for POST /recipient/deliveries/{id}/refuse.

    Returns the updated delivery state and confirmation of refusal.
    """

    delivery_id: UUID
    state: str
    refused_at: datetime


class ContentDownloadResponse(BaseModel):
    """Response metadata for content download.

    The actual content is returned as a streaming response with
    appropriate Content-Type and Content-Disposition headers.
    This model is for documentation/schema purposes.
    """

    content_object_id: UUID
    original_filename: str
    mime_type: str
    size_bytes: int
    sha256: str


class ProofDownloadResponse(BaseModel):
    """Response metadata for proof PDF download.

    The actual PDF is returned as a streaming response.
    This model is for documentation/schema purposes.
    """

    delivery_id: UUID
    proof_type: str
    generated_at: datetime


# Proof types that can be requested
ProofType = Literal["deposit", "notification", "acceptance", "refusal", "receipt", "expiry"]


class ErrorResponse(BaseModel):
    """Standard error response model."""

    error: str
    message: str
    detail: dict | None = None
