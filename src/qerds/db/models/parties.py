"""Party-related models: identities, proofing, and consents.

Covers: REQ-B05 (sender proofing), REQ-E03 (redaction), REQ-F06 (consents)
"""

from __future__ import annotations

# Required at runtime for SQLAlchemy type resolution
import uuid  # noqa: TC003
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qerds.db.models.base import (
    Base,
    ConsentState,
    ConsentType,
    IALLevel,
    OptionalTimestampTZ,
    PartyType,
    ProofingMethod,
    TimestampTZ,
    UUIDPrimaryKey,
)

if TYPE_CHECKING:
    from qerds.db.models.deliveries import Delivery


class Party(Base):
    """Party identity (natural or legal person).

    Stores minimal identity fields with support for redaction profiles.
    Used for both senders and recipients.
    """

    __tablename__ = "parties"

    party_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    party_type: Mapped[PartyType] = mapped_column(
        Enum(PartyType, name="party_type", create_constraint=True),
        nullable=False,
    )

    # Identity fields - stored with redaction support per REQ-E03
    # For natural persons: name parts, email, etc.
    # For legal persons: company name, SIREN/SIRET, etc.
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Extended identity stored as JSONB for flexibility
    # Schema depends on party_type and jurisdiction requirements
    identity_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Redaction profile determines which fields are visible pre-acceptance
    # per REQ-F03 (pre-acceptance redaction)
    redaction_profile: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # External identity provider reference (e.g., FranceConnect sub)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Relationships
    proofing_records: Mapped[list[SenderProofing]] = relationship(
        "SenderProofing",
        back_populates="party",
        cascade="all, delete-orphan",
    )
    consents: Mapped[list[RecipientConsent]] = relationship(
        "RecipientConsent",
        back_populates="recipient_party",
        cascade="all, delete-orphan",
    )
    sent_deliveries: Mapped[list[Delivery]] = relationship(
        "Delivery",
        foreign_keys="Delivery.sender_party_id",
        back_populates="sender_party",
    )
    received_deliveries: Mapped[list[Delivery]] = relationship(
        "Delivery",
        foreign_keys="Delivery.recipient_party_id",
        back_populates="recipient_party",
    )

    __table_args__ = (
        Index("ix_parties_email", "email"),
        Index("ix_parties_external_id", "external_provider", "external_id"),
    )


class SenderProofing(Base):
    """Sender identity proofing record (REQ-B05).

    Records IAL proofing events for senders to support
    "very high confidence" auditability requirements.
    """

    __tablename__ = "sender_proofing"

    proofing_id: Mapped[UUIDPrimaryKey]

    party_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parties.party_id", ondelete="CASCADE"),
        nullable=False,
    )

    # IAL level achieved through this proofing
    ial_level: Mapped[IALLevel] = mapped_column(
        Enum(IALLevel, name="ial_level", create_constraint=True),
        nullable=False,
    )

    # Method used for proofing
    proofing_method: Mapped[ProofingMethod] = mapped_column(
        Enum(ProofingMethod, name="proofing_method", create_constraint=True),
        nullable=False,
    )

    # Reference to evidence object in object store
    proofing_evidence_object_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    proofed_at: Mapped[TimestampTZ]

    # Additional proofing metadata (provider-specific details)
    proofing_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Expiry for time-limited proofing (e.g., FranceConnect session)
    expires_at: Mapped[OptionalTimestampTZ]

    # Relationship
    party: Mapped[Party] = relationship("Party", back_populates="proofing_records")

    __table_args__ = (
        Index("ix_sender_proofing_party_id", "party_id"),
        Index("ix_sender_proofing_proofed_at", "proofed_at"),
    )


class RecipientConsent(Base):
    """Recipient consent record for electronic delivery (REQ-F06).

    Tracks CPCE-required consent for consumer recipients
    to receive electronic registered deliveries.

    Consent lifecycle:
    - PENDING: Initial state, no consent recorded
    - GRANTED: Consent given by the recipient
    - WITHDRAWN: Consent revoked (with audit trail)

    Each consent record represents a specific consent type for a recipient.
    The state tracks the current status, while timestamps and metadata
    provide the full audit trail required for compliance.
    """

    __tablename__ = "recipient_consents"

    consent_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    recipient_party_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parties.party_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Type of consent (jurisdiction-specific)
    consent_type: Mapped[ConsentType] = mapped_column(
        Enum(ConsentType, name="consent_type", create_constraint=True),
        nullable=False,
    )

    # Current consent state
    state: Mapped[ConsentState] = mapped_column(
        Enum(ConsentState, name="consent_state", create_constraint=True),
        nullable=False,
        default=ConsentState.PENDING,
    )

    # When consent was granted (NULL if never granted)
    consented_at: Mapped[OptionalTimestampTZ]

    # Who gave consent (party_id of the consenting user, may differ from recipient)
    consented_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # IP address and user agent for audit trail
    consent_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    consent_user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Reference to consent evidence in object store
    consent_evidence_object_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Withdrawal tracking
    withdrawn_at: Mapped[OptionalTimestampTZ]
    withdrawal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    withdrawal_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    withdrawal_user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Reference to withdrawal evidence in object store
    withdrawal_evidence_object_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Jurisdiction-specific consent metadata (e.g., consent text version, legal basis)
    consent_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationship
    recipient_party: Mapped[Party] = relationship("Party", back_populates="consents")

    __table_args__ = (
        Index("ix_recipient_consents_party_id", "recipient_party_id"),
        Index("ix_recipient_consents_type", "consent_type"),
        Index("ix_recipient_consents_state", "state"),
        # Unique constraint: one consent record per party and consent type
        Index(
            "uq_recipient_consents_party_type",
            "recipient_party_id",
            "consent_type",
            unique=True,
        ),
    )
