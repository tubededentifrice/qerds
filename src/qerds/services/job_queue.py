"""PostgreSQL-backed job queue service for background processing.

Covers: REQ-F04 (scheduled expiry), REQ-H02 (retention enforcement)

This service provides reliable job processing using PostgreSQL's
SELECT ... FOR UPDATE SKIP LOCKED pattern for safe concurrent access.

Key features:
- Atomic job claiming with SKIP LOCKED (no duplicate processing)
- Exponential backoff for retries
- Dead letter handling for failed jobs
- Support for scheduled jobs (run_at timestamp)

Job types supported:
- notification_send: Send email notifications to recipients
- delivery_expire: Mark expired deliveries and create evidence
- log_checkpoint: Seal tamper-evident log checkpoints
- retention_enforce: Archive/delete based on retention policy

Usage:
    from qerds.services.job_queue import JobQueueService
    from sqlalchemy.ext.asyncio import AsyncSession

    async def process_jobs(session: AsyncSession):
        queue = JobQueueService(session)
        job = await queue.claim_job("worker-1")
        if job:
            try:
                # Process the job based on job.job_type
                await queue.complete_job(job.job_id)
            except Exception as e:
                await queue.fail_job(job.job_id, str(e))
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from qerds.db.models.base import JobStatus
from qerds.db.models.jobs import Job

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class JobType(str, Enum):
    """Supported job types for background processing.

    Each job type corresponds to a specific handler in the worker service.
    """

    NOTIFICATION_SEND = "notification_send"
    DELIVERY_EXPIRE = "delivery_expire"
    LOG_CHECKPOINT = "log_checkpoint"
    RETENTION_ENFORCE = "retention_enforce"


class JobQueueError(Exception):
    """Base exception for job queue operations."""

    pass


class JobNotFoundError(JobQueueError):
    """Raised when a job cannot be found."""

    pass


class JobAlreadyClaimedError(JobQueueError):
    """Raised when attempting to claim an already-claimed job."""

    pass


class JobQueueService:
    """PostgreSQL-backed job queue for reliable background processing.

    Uses SELECT ... FOR UPDATE SKIP LOCKED for safe concurrent job claiming.
    Workers can safely compete for jobs without risk of duplicate processing.

    Attributes:
        session: SQLAlchemy async session for database operations.
        default_queue: Default queue name for jobs (default: "default").
        default_max_attempts: Default maximum retry attempts (default: 3).
        default_lock_timeout: Default lock timeout in seconds (default: 300).
        default_base_backoff: Default base backoff in seconds (default: 60).
    """

    def __init__(
        self,
        session: AsyncSession,
        default_queue: str = "default",
        default_max_attempts: int = 3,
        default_lock_timeout: int = 300,
        default_base_backoff: int = 60,
    ) -> None:
        """Initialize the job queue service.

        Args:
            session: SQLAlchemy async session for database operations.
            default_queue: Default queue name for new jobs.
            default_max_attempts: Default maximum retry attempts.
            default_lock_timeout: Default lock timeout in seconds.
            default_base_backoff: Default base backoff in seconds for retries.
        """
        self.session = session
        self.default_queue = default_queue
        self.default_max_attempts = default_max_attempts
        self.default_lock_timeout = default_lock_timeout
        self.default_base_backoff = default_base_backoff

    async def enqueue(
        self,
        job_type: str | JobType,
        payload: dict[str, Any] | None = None,
        run_at: datetime | None = None,
        queue: str | None = None,
        priority: int = 100,
        max_attempts: int | None = None,
        correlation_id: str | None = None,
        parent_job_id: str | None = None,
    ) -> uuid.UUID:
        """Add a new job to the queue.

        Args:
            job_type: Type of job (determines which handler processes it).
            payload: Job-specific data passed to the handler.
            run_at: When the job should be processed. Defaults to now.
            queue: Queue name for routing. Defaults to default_queue.
            priority: Job priority (lower = higher priority). Default 100.
            max_attempts: Maximum retry attempts. Defaults to default_max_attempts.
            correlation_id: Optional ID for tracing related jobs.
            parent_job_id: Optional reference to parent job for job chains.

        Returns:
            UUID of the created job.

        Raises:
            JobQueueError: If job creation fails.
        """
        job_type_value = job_type.value if isinstance(job_type, JobType) else job_type
        now = datetime.now(UTC)

        job = Job(
            job_type=job_type_value,
            status=JobStatus.PENDING,
            run_at=run_at or now,
            payload_json=payload,
            queue=queue or self.default_queue,
            priority=priority,
            max_attempts=max_attempts or self.default_max_attempts,
            lock_timeout_seconds=self.default_lock_timeout,
            base_backoff_seconds=self.default_base_backoff,
            correlation_id=correlation_id,
            parent_job_id=parent_job_id,
        )

        try:
            self.session.add(job)
            await self.session.flush()
            job_id = job.job_id

            logger.info(
                "Job enqueued: job_id=%s, job_type=%s, queue=%s, run_at=%s",
                job_id,
                job_type_value,
                job.queue,
                job.run_at.isoformat(),
            )

            return job_id

        except SQLAlchemyError as e:
            logger.error("Failed to enqueue job: %s", str(e))
            raise JobQueueError(f"Failed to enqueue job: {e}") from e

    async def claim_job(
        self,
        worker_id: str,
        queue: str | None = None,
        job_types: list[str] | None = None,
    ) -> Job | None:
        """Claim the next available job for processing.

        Uses SELECT ... FOR UPDATE SKIP LOCKED to safely claim a job
        without race conditions. Workers can call this concurrently.

        Args:
            worker_id: Unique identifier for the claiming worker.
            queue: Queue to claim from. Defaults to default_queue.
            job_types: Optional list of job types to filter by.

        Returns:
            The claimed Job if one was available, None otherwise.

        Raises:
            JobQueueError: If claim operation fails.
        """
        queue_name = queue or self.default_queue
        now = datetime.now(UTC)

        try:
            # Build the claim query using FOR UPDATE SKIP LOCKED
            # This atomically locks a single row, skipping any already locked
            stmt = (
                select(Job)
                .where(
                    Job.queue == queue_name,
                    Job.status == JobStatus.PENDING,
                    Job.run_at <= now,
                )
                .order_by(Job.priority, Job.run_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )

            # Optionally filter by job types
            if job_types:
                stmt = stmt.where(Job.job_type.in_(job_types))

            result = await self.session.execute(stmt)
            job = result.scalar_one_or_none()

            if job is None:
                return None

            # Update the job to mark it as running
            job.status = JobStatus.RUNNING
            job.locked_at = now
            job.locked_by = worker_id
            job.started_at = now
            job.attempts += 1

            await self.session.flush()

            logger.info(
                "Job claimed: job_id=%s, worker_id=%s, job_type=%s, attempt=%d/%d",
                job.job_id,
                worker_id,
                job.job_type,
                job.attempts,
                job.max_attempts,
            )

            return job

        except SQLAlchemyError as e:
            logger.error("Failed to claim job: %s", str(e))
            raise JobQueueError(f"Failed to claim job: {e}") from e

    async def complete_job(
        self,
        job_id: uuid.UUID,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark a job as successfully completed.

        Args:
            job_id: UUID of the job to complete.
            result: Optional result data to store with the job.

        Raises:
            JobNotFoundError: If the job does not exist.
            JobQueueError: If the update fails.
        """
        now = datetime.now(UTC)

        try:
            job = await self._get_job(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")

            # Calculate duration if started_at is set
            duration_ms = None
            if job.started_at:
                duration = now - job.started_at
                duration_ms = int(duration.total_seconds() * 1000)

            job.status = JobStatus.COMPLETED
            job.completed_at = now
            job.result_json = result
            job.duration_ms = duration_ms
            job.locked_at = None
            job.locked_by = None

            await self.session.flush()

            logger.info(
                "Job completed: job_id=%s, job_type=%s, duration_ms=%s",
                job_id,
                job.job_type,
                duration_ms,
            )

        except JobNotFoundError:
            raise
        except SQLAlchemyError as e:
            logger.error("Failed to complete job %s: %s", job_id, str(e))
            raise JobQueueError(f"Failed to complete job: {e}") from e

    async def fail_job(
        self,
        job_id: uuid.UUID,
        error: str,
    ) -> bool:
        """Mark a job as failed and schedule retry with exponential backoff.

        If the job has exceeded max_attempts, it moves to FAILED status
        (dead letter). Otherwise, it's rescheduled with exponential backoff.

        Args:
            job_id: UUID of the job that failed.
            error: Error message describing the failure.

        Returns:
            True if the job will be retried, False if it's dead-lettered.

        Raises:
            JobNotFoundError: If the job does not exist.
            JobQueueError: If the update fails.
        """
        now = datetime.now(UTC)

        try:
            job = await self._get_job(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")

            job.last_error = error
            job.locked_at = None
            job.locked_by = None

            # Check if we should retry or dead-letter
            if job.attempts >= job.max_attempts:
                # Dead letter: move to FAILED status
                job.status = JobStatus.FAILED
                job.completed_at = now

                # Calculate duration
                if job.started_at:
                    duration = now - job.started_at
                    job.duration_ms = int(duration.total_seconds() * 1000)

                logger.warning(
                    "Job dead-lettered: job_id=%s, job_type=%s, attempts=%d, error=%s",
                    job_id,
                    job.job_type,
                    job.attempts,
                    error,
                )

                await self.session.flush()
                return False

            # Schedule retry with exponential backoff
            # backoff = base_backoff * 2^(attempt-1)
            backoff_seconds = job.base_backoff_seconds * (2 ** (job.attempts - 1))
            job.run_at = now + timedelta(seconds=backoff_seconds)
            job.status = JobStatus.PENDING

            logger.info(
                "Job scheduled for retry: job_id=%s, job_type=%s, "
                "attempt=%d/%d, retry_at=%s, backoff=%ds",
                job_id,
                job.job_type,
                job.attempts,
                job.max_attempts,
                job.run_at.isoformat(),
                backoff_seconds,
            )

            await self.session.flush()
            return True

        except JobNotFoundError:
            raise
        except SQLAlchemyError as e:
            logger.error("Failed to fail job %s: %s", job_id, str(e))
            raise JobQueueError(f"Failed to fail job: {e}") from e

    async def cancel_job(self, job_id: uuid.UUID) -> None:
        """Cancel a pending or running job.

        Args:
            job_id: UUID of the job to cancel.

        Raises:
            JobNotFoundError: If the job does not exist.
            JobQueueError: If the job cannot be cancelled (already completed/failed).
        """
        try:
            job = await self._get_job(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")

            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                raise JobQueueError(f"Cannot cancel job in {job.status.value} status")

            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.now(UTC)
            job.locked_at = None
            job.locked_by = None

            await self.session.flush()

            logger.info("Job cancelled: job_id=%s, job_type=%s", job_id, job.job_type)

        except (JobNotFoundError, JobQueueError):
            raise
        except SQLAlchemyError as e:
            logger.error("Failed to cancel job %s: %s", job_id, str(e))
            raise JobQueueError(f"Failed to cancel job: {e}") from e

    async def get_job(self, job_id: uuid.UUID) -> Job | None:
        """Retrieve a job by ID.

        Args:
            job_id: UUID of the job to retrieve.

        Returns:
            The Job if found, None otherwise.
        """
        return await self._get_job(job_id)

    async def get_pending_count(
        self,
        queue: str | None = None,
        job_type: str | None = None,
    ) -> int:
        """Get the count of pending jobs.

        Args:
            queue: Optional queue to filter by.
            job_type: Optional job type to filter by.

        Returns:
            Number of pending jobs matching the filters.
        """
        stmt = select(Job).where(Job.status == JobStatus.PENDING)

        if queue:
            stmt = stmt.where(Job.queue == queue)
        if job_type:
            stmt = stmt.where(Job.job_type == job_type)

        # Use count subquery for efficiency
        from sqlalchemy import func

        count_stmt = select(func.count()).select_from(stmt.subquery())
        result = await self.session.execute(count_stmt)
        return result.scalar() or 0

    async def get_failed_jobs(
        self,
        queue: str | None = None,
        job_type: str | None = None,
        limit: int = 100,
    ) -> list[Job]:
        """Retrieve failed jobs (dead letter queue).

        Args:
            queue: Optional queue to filter by.
            job_type: Optional job type to filter by.
            limit: Maximum number of jobs to return.

        Returns:
            List of failed jobs.
        """
        stmt = (
            select(Job)
            .where(Job.status == JobStatus.FAILED)
            .order_by(Job.completed_at.desc())
            .limit(limit)
        )

        if queue:
            stmt = stmt.where(Job.queue == queue)
        if job_type:
            stmt = stmt.where(Job.job_type == job_type)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def retry_failed_job(self, job_id: uuid.UUID) -> None:
        """Manually retry a failed job (move from dead letter back to pending).

        Resets the attempt counter and schedules the job for immediate execution.

        Args:
            job_id: UUID of the failed job to retry.

        Raises:
            JobNotFoundError: If the job does not exist.
            JobQueueError: If the job is not in FAILED status.
        """
        try:
            job = await self._get_job(job_id)
            if job is None:
                raise JobNotFoundError(f"Job not found: {job_id}")

            if job.status != JobStatus.FAILED:
                raise JobQueueError(
                    f"Can only retry FAILED jobs, current status: {job.status.value}"
                )

            # Reset job for retry
            job.status = JobStatus.PENDING
            job.run_at = datetime.now(UTC)
            job.attempts = 0
            job.completed_at = None
            job.last_error = None
            job.duration_ms = None

            await self.session.flush()

            logger.info(
                "Failed job queued for retry: job_id=%s, job_type=%s",
                job_id,
                job.job_type,
            )

        except (JobNotFoundError, JobQueueError):
            raise
        except SQLAlchemyError as e:
            logger.error("Failed to retry job %s: %s", job_id, str(e))
            raise JobQueueError(f"Failed to retry job: {e}") from e

    async def cleanup_stale_jobs(
        self,
        stale_threshold_seconds: int = 600,
    ) -> int:
        """Reset jobs that have been running too long (stale locks).

        Workers may crash while processing jobs. This method identifies
        jobs that have been locked longer than the threshold and resets
        them for reprocessing.

        Args:
            stale_threshold_seconds: How long a job can be locked before
                being considered stale. Default 600 (10 minutes).

        Returns:
            Number of stale jobs reset.
        """
        now = datetime.now(UTC)
        threshold = now - timedelta(seconds=stale_threshold_seconds)

        try:
            # Find stale jobs
            stmt = (
                update(Job)
                .where(
                    Job.status == JobStatus.RUNNING,
                    Job.locked_at < threshold,
                )
                .values(
                    status=JobStatus.PENDING,
                    locked_at=None,
                    locked_by=None,
                    run_at=now,  # Reschedule for immediate retry
                )
                .returning(Job.job_id)
            )

            result = await self.session.execute(stmt)
            stale_job_ids = list(result.scalars().all())

            if stale_job_ids:
                logger.warning(
                    "Reset %d stale jobs: %s",
                    len(stale_job_ids),
                    stale_job_ids,
                )

            return len(stale_job_ids)

        except SQLAlchemyError as e:
            logger.error("Failed to cleanup stale jobs: %s", str(e))
            raise JobQueueError(f"Failed to cleanup stale jobs: {e}") from e

    async def _get_job(self, job_id: uuid.UUID) -> Job | None:
        """Internal method to retrieve a job by ID.

        Args:
            job_id: UUID of the job to retrieve.

        Returns:
            The Job if found, None otherwise.
        """
        stmt = select(Job).where(Job.job_id == job_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
