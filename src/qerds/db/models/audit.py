"""Audit-related models: log records and audit packs.

Covers: REQ-C05 (immutability), REQ-D08 (logging), REQ-H01 (exportability),
        REQ-H03 (audit review)
"""

from __future__ import annotations

import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution

from sqlalchemy import BigInteger, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from qerds.db.models.base import (
    AuditStream,
    Base,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)


class AuditLogRecord(Base):
    """Tamper-evident audit log entry (REQ-C05, REQ-D08, REQ-H03).

    Each record is chained to the previous via prev_record_hash,
    creating an immutable, verifiable audit trail.
    """

    __tablename__ = "audit_log_records"

    record_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Stream categorization for efficient querying
    stream: Mapped[AuditStream] = mapped_column(
        Enum(AuditStream, name="audit_stream", create_constraint=True),
        nullable=False,
    )

    # Sequence number within the stream (monotonically increasing)
    # This enables detection of gaps/missing records
    seq_no: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Hash of this record's payload for integrity verification
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Hash of the previous record in this stream (chain link)
    # First record in a stream has NULL prev_record_hash
    prev_record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Reference to full payload in object store
    # Payload is stored separately to keep the index table small
    payload_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Reference to sealed checkpoint that includes this record
    # Checkpoints are periodically created with timestamped signatures
    sealed_checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Event type for quick filtering without loading payload
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Actor information for access review
    actor_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Resource reference (delivery_id, user_id, etc.)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Summary metadata for display without loading full payload
    summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_audit_log_records_stream", "stream"),
        # Unique sequence within each stream
        Index("ix_audit_log_records_stream_seq", "stream", "seq_no", unique=True),
        Index("ix_audit_log_records_created_at", "created_at"),
        Index("ix_audit_log_records_event_type", "event_type"),
        Index("ix_audit_log_records_actor", "actor_type", "actor_id"),
        Index("ix_audit_log_records_resource", "resource_type", "resource_id"),
        Index("ix_audit_log_records_checkpoint", "sealed_checkpoint_id"),
    )


class AuditPack(Base):
    """Exportable audit pack for external review (REQ-H01).

    Contains a range of audit records with sealed evidence,
    suitable for export to auditors or regulatory bodies.
    """

    __tablename__ = "audit_packs"

    audit_pack_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Time range covered by this pack
    range_start: Mapped[TimestampTZ]
    range_end: Mapped[TimestampTZ]

    # Stream(s) included in this pack
    streams: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Who generated this pack
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    generated_at: Mapped[TimestampTZ]

    # Reference to the pack archive in object store
    object_store_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Reference to sealed evidence object for the pack
    sealed_evidence_object_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.evidence_object_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Pack metadata (record count, size, etc.)
    pack_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Human-readable description/notes
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Verification status
    verified_at: Mapped[OptionalTimestampTZ]
    verified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_audit_packs_range", "range_start", "range_end"),
        Index("ix_audit_packs_generated_at", "generated_at"),
    )
