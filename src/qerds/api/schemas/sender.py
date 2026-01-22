"""Pydantic schemas for sender API endpoints.

Covers: REQ-B01 (deposit), REQ-B02 (content binding), REQ-B05 (sender proofing)

These schemas define the request/response models for sender operations
including delivery creation, content upload, and proof retrieval.
"""

from __future__ import annotations

# NOTE: datetime and UUID must remain at runtime for Pydantic validation
from datetime import datetime  # noqa: TC003
from typing import Annotated, Any
from uuid import UUID  # noqa: TC003

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# -----------------------------------------------------------------------------
# Delivery Creation Schemas
# -----------------------------------------------------------------------------


class RecipientInput(BaseModel):
    """Recipient information for delivery creation."""

    email: EmailStr = Field(..., description="Recipient email address")
    display_name: str | None = Field(None, max_length=255, description="Recipient display name")

    model_config = ConfigDict(extra="forbid")


class CreateDeliveryRequest(BaseModel):
    """Request schema for creating a draft delivery.

    Creates a new delivery in DRAFT state with recipient information
    and optional metadata. Content must be uploaded separately.
    """

    recipient: RecipientInput = Field(..., description="Recipient information")
    subject: str | None = Field(
        None,
        max_length=500,
        description="Subject/title for the delivery (may be redacted pre-acceptance)",
    )
    message: str | None = Field(
        None,
        max_length=10000,
        description="Optional message body",
    )
    jurisdiction_profile: str = Field(
        "eidas",
        pattern=r"^(eidas|fr_lre)$",
        description="Jurisdiction profile (eidas or fr_lre)",
    )
    delivery_metadata: dict[str, Any] | None = Field(
        None,
        description="Optional delivery metadata (jurisdiction-specific extensions)",
    )

    model_config = ConfigDict(extra="forbid")


class DeliveryResponse(BaseModel):
    """Response schema for delivery details."""

    delivery_id: UUID = Field(..., description="Unique delivery identifier")
    state: str = Field(..., description="Current delivery state")
    sender_party_id: UUID = Field(..., description="Sender party UUID")
    recipient_party_id: UUID = Field(..., description="Recipient party UUID")
    recipient_email: str | None = Field(None, description="Recipient email address")
    recipient_name: str | None = Field(None, description="Recipient display name")
    subject: str | None = Field(None, description="Delivery subject")
    message: str | None = Field(None, description="Delivery message")
    jurisdiction_profile: str = Field(..., description="Jurisdiction profile")
    acceptance_deadline_at: datetime | None = Field(
        None, description="Acceptance deadline (15-day window)"
    )
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    deposited_at: datetime | None = Field(None, description="Deposit timestamp")
    notified_at: datetime | None = Field(None, description="Notification timestamp")
    available_at: datetime | None = Field(None, description="Available timestamp")
    completed_at: datetime | None = Field(None, description="Completion timestamp")
    content_objects: list[ContentObjectResponse] = Field(
        default_factory=list, description="Attached content objects"
    )

    model_config = ConfigDict(from_attributes=True)


class DeliveryListResponse(BaseModel):
    """Response schema for listing deliveries."""

    items: list[DeliverySummary] = Field(..., description="List of deliveries")
    total: int = Field(..., description="Total number of matching deliveries")
    offset: int = Field(0, description="Pagination offset")
    limit: int = Field(20, description="Page size")


class DeliverySummary(BaseModel):
    """Summary response for delivery listing (less detail than full response)."""

    delivery_id: UUID = Field(..., description="Unique delivery identifier")
    state: str = Field(..., description="Current delivery state")
    recipient_email: str | None = Field(None, description="Recipient email")
    recipient_name: str | None = Field(None, description="Recipient name")
    subject: str | None = Field(None, description="Delivery subject")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    content_count: int = Field(0, description="Number of content objects")

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Content Upload Schemas
# -----------------------------------------------------------------------------


class ContentUploadRequest(BaseModel):
    """Request schema for content upload metadata.

    The actual file content is uploaded as multipart form data.
    This schema validates the metadata portion.
    """

    original_filename: str = Field(
        ...,
        max_length=500,
        description="Original filename for the content",
    )
    mime_type: str = Field(
        ...,
        max_length=255,
        description="MIME type of the content",
    )
    sha256: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[a-fA-F0-9]{64}$",
        description="SHA-256 hash of the content (hex-encoded, 64 chars)",
    )
    content_metadata: dict[str, Any] | None = Field(
        None,
        description="Additional content metadata",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("sha256")
    @classmethod
    def lowercase_sha256(cls, v: str) -> str:
        """Normalize SHA-256 to lowercase."""
        return v.lower()


class ContentObjectResponse(BaseModel):
    """Response schema for a content object."""

    content_object_id: UUID = Field(..., description="Content object UUID")
    sha256: str = Field(..., description="SHA-256 hash of the content")
    size_bytes: int = Field(..., description="Content size in bytes")
    mime_type: str = Field(..., description="MIME type")
    original_filename: str | None = Field(None, description="Original filename")
    created_at: datetime = Field(..., description="Upload timestamp")

    model_config = ConfigDict(from_attributes=True)


class ContentUploadResponse(BaseModel):
    """Response schema for successful content upload."""

    content_object_id: UUID = Field(..., description="Created content object UUID")
    sha256: str = Field(..., description="Verified SHA-256 hash")
    size_bytes: int = Field(..., description="Uploaded content size")
    storage_key: str = Field(..., description="Object store key")


# -----------------------------------------------------------------------------
# Deposit Schemas
# -----------------------------------------------------------------------------


class DepositRequest(BaseModel):
    """Request schema for depositing (submitting) a delivery.

    Transitions the delivery from DRAFT to DEPOSITED state,
    generating EVT_DEPOSITED evidence event.
    """

    # Optional confirmation that content is complete
    confirm_complete: bool = Field(
        True,
        description="Confirm all content has been uploaded",
    )

    model_config = ConfigDict(extra="forbid")


class DepositResponse(BaseModel):
    """Response schema for successful deposit."""

    delivery_id: UUID = Field(..., description="Delivery UUID")
    state: str = Field(..., description="New state (deposited)")
    deposited_at: datetime = Field(..., description="Deposit timestamp")
    evidence_event_id: UUID = Field(..., description="EVT_DEPOSITED event UUID")
    content_hashes: list[str] = Field(..., description="SHA-256 hashes of all content")


# -----------------------------------------------------------------------------
# Proof Schemas
# -----------------------------------------------------------------------------


class ProofType(BaseModel):
    """Available proof type information."""

    type: str = Field(..., description="Proof type identifier")
    name: str = Field(..., description="Human-readable proof name")
    available: bool = Field(..., description="Whether this proof is available")
    event_type: str | None = Field(None, description="Associated evidence event type")
    generated_at: datetime | None = Field(None, description="When proof was generated")


class ProofListResponse(BaseModel):
    """Response schema for listing available proofs."""

    delivery_id: UUID = Field(..., description="Delivery UUID")
    proofs: list[ProofType] = Field(..., description="Available proof types")


# -----------------------------------------------------------------------------
# Pagination and Filtering
# -----------------------------------------------------------------------------


# Common pagination parameters as annotated types for use in path operations
PageOffset = Annotated[int, Field(ge=0, default=0, description="Pagination offset")]
PageLimit = Annotated[int, Field(ge=1, le=100, default=20, description="Page size")]


class DeliveryListParams(BaseModel):
    """Query parameters for listing deliveries."""

    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(20, ge=1, le=100, description="Page size")
    state: str | None = Field(None, description="Filter by state")
    sort: str = Field("created_at", description="Sort field")
    order: str = Field("desc", pattern=r"^(asc|desc)$", description="Sort order")


# Forward references for self-referential models
DeliveryListResponse.model_rebuild()
