"""Delivery-related models: deliveries and content objects.

Covers: REQ-B01 (integrity), REQ-B02 (content binding), REQ-C01 (state machine),
        REQ-E01 (confidentiality), REQ-F03 (pre-acceptance redaction), REQ-F04 (15-day window)
"""

from __future__ import annotations

import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Enum, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qerds.db.models.base import (
    Base,
    DeliveryState,
    EncryptionScheme,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)

if TYPE_CHECKING:
    from qerds.db.models.evidence import EvidenceEvent
    from qerds.db.models.parties import Party


class Delivery(Base):
    """Delivery state machine (REQ-C01).

    Represents a single registered delivery from sender to recipient,
    tracking its lifecycle from draft through completion/expiry.
    """

    __tablename__ = "deliveries"

    delivery_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Current state in the delivery lifecycle
    state: Mapped[DeliveryState] = mapped_column(
        Enum(DeliveryState, name="delivery_state", create_constraint=True),
        nullable=False,
        default=DeliveryState.DRAFT,
    )

    # Sender party reference
    sender_party_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parties.party_id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Recipient party reference
    recipient_party_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parties.party_id", ondelete="RESTRICT"),
        nullable=False,
    )

    # Jurisdiction profile determines CPCE-specific behavior
    # e.g., 'eidas' for EU-wide, 'fr_lre' for French LRE requirements
    jurisdiction_profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="eidas",
    )

    # 15-day acceptance window deadline per REQ-F04
    acceptance_deadline_at: Mapped[OptionalTimestampTZ]

    # Pre-acceptance redaction profile per REQ-F03
    # Determines which sender/content fields are visible before acceptance
    pre_acceptance_redaction_profile: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # Subject/title for the delivery (may be redacted pre-acceptance)
    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Optional message body
    message: Mapped[str | None] = mapped_column(String(10000), nullable=True)

    # Delivery metadata (jurisdiction-specific extensions)
    # Note: named 'delivery_metadata' to avoid conflict with SQLAlchemy's reserved 'metadata'
    delivery_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Key lifecycle timestamps
    deposited_at: Mapped[OptionalTimestampTZ]
    notified_at: Mapped[OptionalTimestampTZ]
    available_at: Mapped[OptionalTimestampTZ]
    completed_at: Mapped[OptionalTimestampTZ]  # accepted/refused/received/expired

    # Relationships
    sender_party: Mapped[Party] = relationship(
        "Party",
        foreign_keys=[sender_party_id],
        back_populates="sent_deliveries",
    )
    recipient_party: Mapped[Party] = relationship(
        "Party",
        foreign_keys=[recipient_party_id],
        back_populates="received_deliveries",
    )
    content_objects: Mapped[list[ContentObject]] = relationship(
        "ContentObject",
        back_populates="delivery",
        cascade="all, delete-orphan",
    )
    evidence_events: Mapped[list[EvidenceEvent]] = relationship(
        "EvidenceEvent",
        back_populates="delivery",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_deliveries_sender_party_id", "sender_party_id"),
        Index("ix_deliveries_recipient_party_id", "recipient_party_id"),
        Index("ix_deliveries_state", "state"),
        Index("ix_deliveries_created_at", "created_at"),
        Index("ix_deliveries_acceptance_deadline", "acceptance_deadline_at"),
    )


class ContentObject(Base):
    """Encrypted content reference (REQ-B02, REQ-E01).

    Represents a file or document attached to a delivery,
    stored in the object store with integrity binding.
    """

    __tablename__ = "content_objects"

    content_object_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    delivery_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("deliveries.delivery_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Content integrity (REQ-B02) - SHA-256 digest of original content
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # Size in bytes for quota/validation
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # MIME type for content handling
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)

    # Original filename (may be redacted pre-acceptance)
    original_filename: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Object store reference
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)

    # Encryption scheme for confidentiality (REQ-E01)
    encryption_scheme: Mapped[EncryptionScheme] = mapped_column(
        Enum(EncryptionScheme, name="encryption_scheme", create_constraint=True),
        nullable=False,
        default=EncryptionScheme.AES_256_GCM,
    )

    # Reference to encryption metadata (wrapped DEK, recipient key ID, etc.)
    # Deprecated: Use encryption_metadata JSONB column instead
    encryption_metadata_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Envelope encryption metadata (REQ-E01)
    # Contains: version, algorithm, nonce, wrapped_dek, kek_id, content_hash, encrypted_at
    encryption_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Additional content metadata
    content_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationship
    delivery: Mapped[Delivery] = relationship(
        "Delivery",
        back_populates="content_objects",
    )

    __table_args__ = (
        Index("ix_content_objects_delivery_id", "delivery_id"),
        Index("ix_content_objects_sha256", "sha256"),
    )
