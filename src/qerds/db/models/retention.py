"""Retention-related models: policies and actions.

Covers: REQ-F05 (one-year proof retention), REQ-H02 (retention enforcement)
"""

from __future__ import annotations

# Required at runtime for SQLAlchemy type resolution (noqa: TC003 for both)
import uuid  # noqa: TC003
from datetime import datetime  # noqa: TC003

from sqlalchemy import BigInteger, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from qerds.db.models.base import (
    Base,
    OptionalTimestampTZ,
    RetentionActionType,
    TimestampTZ,
    UUIDPrimaryKey,
)


class RetentionPolicy(Base):
    """Retention policy definition (REQ-F05, REQ-H02).

    Defines minimum retention periods for different artifact types.
    CPCE requires one-year minimum retention for delivery proofs.
    """

    __tablename__ = "retention_policies"

    policy_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Type of artifact this policy applies to
    # e.g., 'evidence_object', 'content_object', 'audit_log', 'delivery'
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Policy version for tracking changes
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # Minimum retention period in days (CPCE: 365 for proofs)
    minimum_retention_days: Mapped[int] = mapped_column(nullable=False)

    # Optional maximum retention (for data minimization/GDPR)
    maximum_retention_days: Mapped[int | None] = mapped_column(nullable=True)

    # Whether this policy is currently active
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Jurisdiction this policy applies to (null = all)
    jurisdiction_profile: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Action to take when retention expires
    expiry_action: Mapped[RetentionActionType] = mapped_column(
        Enum(RetentionActionType, name="retention_action_type", create_constraint=True),
        nullable=False,
        default=RetentionActionType.ARCHIVE,
    )

    # Human-readable description
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Policy metadata (additional rules, exceptions, etc.)
    policy_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_retention_policies_artifact_type", "artifact_type"),
        Index("ix_retention_policies_is_active", "is_active"),
        Index(
            "ix_retention_policies_type_jurisdiction",
            "artifact_type",
            "jurisdiction_profile",
        ),
    )


class RetentionAction(Base):
    """Record of a retention enforcement action (REQ-H02).

    Tracks when artifacts are archived or deleted per retention policy.
    Provides audit trail for compliance verification.
    """

    __tablename__ = "retention_actions"

    action_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Reference to the artifact being acted upon
    artifact_type: Mapped[str] = mapped_column(String(100), nullable=False)
    artifact_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Type of action taken
    action_type: Mapped[RetentionActionType] = mapped_column(
        Enum(RetentionActionType, name="retention_action_type", create_constraint=True),
        nullable=False,
    )

    # Policy that triggered this action
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("retention_policies.policy_id", ondelete="SET NULL"),
        nullable=True,
    )

    # When the action was executed
    executed_at: Mapped[datetime] = mapped_column(nullable=False)

    # Who/what executed the action
    executed_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # Result of the action
    result: Mapped[str] = mapped_column(String(50), nullable=False)  # success/failure
    result_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Reference to audit log record for this action
    audit_log_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("audit_log_records.record_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Archive location (if action_type is ARCHIVE)
    archive_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Original artifact metadata (preserved before deletion)
    artifact_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Size of artifact in bytes (for capacity tracking)
    artifact_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Original retention deadline that triggered this action
    retention_deadline: Mapped[OptionalTimestampTZ]

    __table_args__ = (
        Index("ix_retention_actions_artifact_type", "artifact_type"),
        Index("ix_retention_actions_executed_at", "executed_at"),
        Index("ix_retention_actions_result", "result"),
        Index("ix_retention_actions_policy_id", "policy_id"),
    )
