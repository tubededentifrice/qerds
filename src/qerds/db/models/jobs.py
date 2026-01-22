"""Job queue model for PostgreSQL-backed background processing.

Covers: REQ-F04 (scheduled expiry), REQ-H02 (retention enforcement)

This provides a simple, reliable job queue using PostgreSQL:
- SKIP LOCKED for concurrent worker safety
- Retry with exponential backoff
- Dead letter handling for failed jobs
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 - required at runtime for SQLAlchemy type resolution

from sqlalchemy import BigInteger, Enum, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qerds.db.models.base import (
    Base,
    JobStatus,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)


class Job(Base):
    """Background job for async processing.

    Jobs are picked up by workers using SELECT ... FOR UPDATE SKIP LOCKED
    to ensure safe concurrent processing without external queue infrastructure.
    """

    __tablename__ = "jobs"

    job_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Job type determines which handler processes it
    # e.g., 'send_notification', 'expire_delivery', 'enforce_retention'
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Current job status
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status", create_constraint=True),
        nullable=False,
        default=JobStatus.PENDING,
    )

    # When the job should be run (for scheduled jobs)
    run_at: Mapped[datetime] = mapped_column(nullable=False)

    # Lock tracking for concurrent workers
    locked_at: Mapped[OptionalTimestampTZ]
    locked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Lock timeout in seconds (workers re-acquire if lock expires)
    lock_timeout_seconds: Mapped[int] = mapped_column(default=300, nullable=False)

    # Retry tracking
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(default=3, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Backoff configuration (seconds for next retry, doubles each attempt)
    base_backoff_seconds: Mapped[int] = mapped_column(default=60, nullable=False)

    # Job payload (handler-specific data)
    payload_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Job result (for completed jobs)
    result_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Completion tracking
    started_at: Mapped[OptionalTimestampTZ]
    completed_at: Mapped[OptionalTimestampTZ]

    # Priority (lower = higher priority)
    priority: Mapped[int] = mapped_column(default=100, nullable=False)

    # Queue name for routing to specific workers
    queue: Mapped[str] = mapped_column(String(100), default="default", nullable=False)

    # Correlation ID for tracing related jobs
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Reference to parent job (for job chains)
    parent_job_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Estimated duration in seconds (for scheduling)
    estimated_duration_seconds: Mapped[int | None] = mapped_column(nullable=True)

    # Actual duration in milliseconds (for metrics)
    duration_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    __table_args__ = (
        # Primary query for workers: pending jobs ready to run, ordered by priority
        Index(
            "ix_jobs_queue_pending",
            "queue",
            "status",
            "run_at",
            "priority",
        ),
        Index("ix_jobs_status", "status"),
        Index("ix_jobs_job_type", "job_type"),
        Index("ix_jobs_run_at", "run_at"),
        Index("ix_jobs_correlation_id", "correlation_id"),
        # For cleanup of old completed jobs
        Index("ix_jobs_completed_at", "completed_at"),
    )
