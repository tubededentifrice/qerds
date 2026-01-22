"""Evidence-related models: events, objects, and policy snapshots.

Covers: REQ-A03 (policy), REQ-C05 (immutability), REQ-G02 (qualification),
        REQ-H05 (policy snapshots)
"""

from __future__ import annotations

import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qerds.db.models.base import (
    ActorType,
    Base,
    EventType,
    OptionalTimestampTZ,
    QualificationLabel,
    TimestampTZ,
    UUIDPrimaryKey,
)

if TYPE_CHECKING:
    from qerds.db.models.deliveries import Delivery


class PolicySnapshot(Base):
    """Versioned policy/configuration snapshot (REQ-A03, REQ-H05).

    Captures the state of policies and configuration at a point in time
    to ensure evidence can be verified against the rules that were
    in effect when the event occurred.
    """

    __tablename__ = "policy_snapshots"

    policy_snapshot_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Who created this snapshot (admin user or system)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # Version identifier for human reference
    version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Human-readable description of what changed
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # References to policy/CPS documents in object store
    doc_refs: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Configuration values (minimal JSONB, keep stable schema)
    config_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Hash of the snapshot for integrity verification
    snapshot_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Whether this snapshot is currently active
    is_active: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    evidence_events: Mapped[list[EvidenceEvent]] = relationship(
        "EvidenceEvent",
        back_populates="policy_snapshot",
    )

    __table_args__ = (
        Index("ix_policy_snapshots_created_at", "created_at"),
        Index("ix_policy_snapshots_is_active", "is_active"),
    )


class EvidenceEvent(Base):
    """Lifecycle event requiring evidence capture.

    Records significant events in the delivery lifecycle that
    must be preserved for compliance and audit purposes.
    """

    __tablename__ = "evidence_events"

    event_id: Mapped[UUIDPrimaryKey]

    delivery_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("deliveries.delivery_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Type of event
    event_type: Mapped[EventType] = mapped_column(
        Enum(EventType, name="event_type", create_constraint=True),
        nullable=False,
    )

    # When the event occurred (authoritative timestamp)
    event_time: Mapped[TimestampTZ]

    # Type of actor who triggered/caused the event
    actor_type: Mapped[ActorType] = mapped_column(
        Enum(ActorType, name="actor_type", create_constraint=True),
        nullable=False,
    )

    # Reference to the actor (party_id, admin_user_id, api_client_id, or 'system')
    actor_ref: Mapped[str] = mapped_column(String(255), nullable=False)

    # Policy snapshot that was in effect when event occurred
    policy_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy_snapshots.policy_snapshot_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Event-specific metadata
    event_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    delivery: Mapped[Delivery] = relationship(
        "Delivery",
        back_populates="evidence_events",
    )
    policy_snapshot: Mapped[PolicySnapshot | None] = relationship(
        "PolicySnapshot",
        back_populates="evidence_events",
    )
    evidence_objects: Mapped[list[EvidenceObject]] = relationship(
        "EvidenceObject",
        back_populates="event",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_evidence_events_delivery_id", "delivery_id"),
        Index("ix_evidence_events_event_type", "event_type"),
        Index("ix_evidence_events_event_time", "event_time"),
        Index("ix_evidence_events_actor_type", "actor_type"),
    )


class EvidenceObject(Base):
    """Sealed evidence artifact (REQ-C05, REQ-G02).

    Represents a cryptographically sealed evidence bundle
    with provider attestation and optional qualified timestamp.
    """

    __tablename__ = "evidence_objects"

    evidence_object_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_events.event_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Digest of the canonical evidence payload for integrity
    canonical_payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    # Reference to provider attestation (signature) in object store
    provider_attestation_blob_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Reference to time attestation (timestamp token) in object store
    time_attestation_blob_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Reference to complete verification bundle in object store
    verification_bundle_blob_ref: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Qualification status per REQ-G02
    # IMPORTANT: Only mark as QUALIFIED when all requirements are met
    qualification_label: Mapped[QualificationLabel] = mapped_column(
        Enum(QualificationLabel, name="qualification_label", create_constraint=True),
        nullable=False,
        default=QualificationLabel.NON_QUALIFIED,
    )

    # Human-readable reason for qualification status
    qualification_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Additional evidence metadata
    evidence_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # When evidence was sealed (may differ from created_at)
    sealed_at: Mapped[OptionalTimestampTZ]

    # Relationship
    event: Mapped[EvidenceEvent] = relationship(
        "EvidenceEvent",
        back_populates="evidence_objects",
    )

    __table_args__ = (
        Index("ix_evidence_objects_event_id", "event_id"),
        Index("ix_evidence_objects_qualification_label", "qualification_label"),
        Index("ix_evidence_objects_created_at", "created_at"),
    )
