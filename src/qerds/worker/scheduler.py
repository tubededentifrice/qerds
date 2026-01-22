"""Job scheduler for periodic background tasks.

Covers: REQ-F04 (scheduled expiry), REQ-C05 (audit log sealing), REQ-H02 (retention enforcement)

This module provides scheduling for periodic jobs:
- Expiry check: Runs periodically to find expired deliveries
- Checkpoint sealing: Hourly seal of audit log chains
- Retention enforcement: Daily cleanup per retention policy
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from qerds.db.models.base import JobStatus
from qerds.db.models.jobs import Job
from qerds.services.job_queue import JobQueueService, JobType

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


@dataclass
class ScheduledJob:
    """Definition of a scheduled periodic job.

    Attributes:
        job_type: Type of job to schedule.
        interval: Time between job executions.
        payload: Job-specific payload data.
        queue: Queue to schedule the job on.
        priority: Job priority (lower = higher priority).
        enabled: Whether this scheduled job is active.
        last_scheduled: When the job was last scheduled.
    """

    job_type: str
    interval: timedelta
    payload: dict[str, Any] = field(default_factory=dict)
    queue: str = "default"
    priority: int = 100
    enabled: bool = True
    last_scheduled: datetime | None = None


# Default scheduled jobs for QERDS worker
DEFAULT_SCHEDULES = [
    # Check for expired deliveries every 5 minutes
    ScheduledJob(
        job_type=JobType.DELIVERY_EXPIRE.value,
        interval=timedelta(minutes=5),
        payload={"batch_size": 100},
        priority=50,
    ),
    # Seal audit log checkpoints every hour
    ScheduledJob(
        job_type=JobType.LOG_CHECKPOINT.value,
        interval=timedelta(hours=1),
        payload={"verify_chain": True},
        priority=80,
    ),
    # Enforce retention policies daily at low priority
    ScheduledJob(
        job_type=JobType.RETENTION_ENFORCE.value,
        interval=timedelta(hours=24),
        payload={"batch_size": 100, "dry_run": False},
        priority=200,  # Low priority - runs when system is idle
    ),
]


class Scheduler:
    """Job scheduler that ensures periodic jobs are enqueued.

    The scheduler checks if a scheduled job needs to run based on
    when it was last executed. It avoids duplicate scheduling by
    checking if a pending job already exists.

    Example:
        scheduler = Scheduler(session)
        scheduler.add_schedule(ScheduledJob(
            job_type="my_job",
            interval=timedelta(hours=1),
        ))
        await scheduler.tick()  # Check and schedule due jobs
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the scheduler.

        Args:
            session: Database session for job operations.
        """
        self.session = session
        self._schedules: list[ScheduledJob] = []
        self._job_queue = JobQueueService(session)

    def add_schedule(self, schedule: ScheduledJob) -> None:
        """Add a scheduled job definition.

        Args:
            schedule: The scheduled job configuration.
        """
        self._schedules.append(schedule)
        logger.debug(
            "Added schedule: job_type=%s, interval=%s",
            schedule.job_type,
            schedule.interval,
        )

    def add_default_schedules(self) -> None:
        """Add the default QERDS scheduled jobs."""
        for schedule in DEFAULT_SCHEDULES:
            self.add_schedule(schedule)
        logger.info("Added %d default schedules", len(DEFAULT_SCHEDULES))

    async def tick(self) -> list[str]:
        """Check all schedules and enqueue jobs that are due.

        Returns:
            List of job types that were scheduled.
        """
        now = datetime.now(UTC)
        scheduled: list[str] = []

        for schedule in self._schedules:
            if not schedule.enabled:
                continue

            # Check if this job is due to run
            if not self._is_due(schedule, now):
                continue

            # Check if there's already a pending job of this type
            if await self._has_pending_job(schedule.job_type, schedule.queue):
                logger.debug(
                    "Skipping schedule - pending job exists: job_type=%s",
                    schedule.job_type,
                )
                continue

            # Schedule the job
            try:
                await self._job_queue.enqueue(
                    job_type=schedule.job_type,
                    payload=schedule.payload,
                    queue=schedule.queue,
                    priority=schedule.priority,
                )
                schedule.last_scheduled = now
                scheduled.append(schedule.job_type)

                logger.info(
                    "Scheduled job: job_type=%s, queue=%s, next_due=%s",
                    schedule.job_type,
                    schedule.queue,
                    (now + schedule.interval).isoformat(),
                )

            except Exception as e:
                logger.exception(
                    "Failed to schedule job: job_type=%s, error=%s",
                    schedule.job_type,
                    e,
                )

        return scheduled

    def _is_due(self, schedule: ScheduledJob, now: datetime) -> bool:
        """Check if a scheduled job is due to run.

        Args:
            schedule: The scheduled job configuration.
            now: Current timestamp.

        Returns:
            True if the job should be scheduled now.
        """
        if schedule.last_scheduled is None:
            # Never scheduled - due immediately
            return True

        next_run = schedule.last_scheduled + schedule.interval
        return now >= next_run

    async def _has_pending_job(self, job_type: str, queue: str) -> bool:
        """Check if there's a pending or running job of this type.

        Args:
            job_type: The job type to check.
            queue: The queue to check.

        Returns:
            True if a pending/running job exists.
        """
        stmt = (
            select(Job)
            .where(
                Job.job_type == job_type,
                Job.queue == queue,
                Job.status.in_([JobStatus.PENDING, JobStatus.RUNNING]),
            )
            .limit(1)
        )

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none() is not None


async def run_scheduler_loop(
    session_factory: async_sessionmaker[AsyncSession],
    schedules: list[ScheduledJob] | None = None,
    check_interval: float = 60.0,
    shutdown_event: asyncio.Event | None = None,
) -> None:
    """Run the scheduler loop as a background task.

    This function runs continuously, checking schedules at regular intervals
    and enqueuing jobs that are due.

    Args:
        session_factory: Factory for creating database sessions.
        schedules: Optional list of schedules (uses defaults if None).
        check_interval: Seconds between schedule checks.
        shutdown_event: Event to signal shutdown.
    """
    if shutdown_event is None:
        shutdown_event = asyncio.Event()

    logger.info(
        "Scheduler starting: check_interval=%ss, schedules=%d",
        check_interval,
        len(schedules) if schedules else len(DEFAULT_SCHEDULES),
    )

    while not shutdown_event.is_set():
        try:
            async with session_factory() as session:
                scheduler = Scheduler(session)

                # Add schedules
                if schedules:
                    for schedule in schedules:
                        scheduler.add_schedule(schedule)
                else:
                    scheduler.add_default_schedules()

                # Check and schedule due jobs
                scheduled = await scheduler.tick()
                if scheduled:
                    await session.commit()
                    logger.debug("Scheduled jobs: %s", scheduled)

        except Exception as e:
            logger.exception("Error in scheduler loop: %s", e)

        # Wait for next check interval (uses wait_for to allow shutdown)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                shutdown_event.wait(),
                timeout=check_interval,
            )

    logger.info("Scheduler stopped")
