"""QERDS Worker service entry point.

Covers: REQ-F04 (scheduled expiry), REQ-C05 (audit log sealing), REQ-H02 (retention enforcement)

This module provides the main Worker class that:
- Polls the job queue for available jobs
- Dispatches jobs to appropriate handlers
- Handles graceful shutdown via SIGTERM/SIGINT
- Manages retry logic via the JobQueueService
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from qerds.services.job_queue import JobQueueService, JobType

if TYPE_CHECKING:
    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)

# Type alias for job handlers
JobHandler = Callable[[AsyncSession, "Job"], Coroutine[Any, Any, dict[str, Any] | None]]


@dataclass
class WorkerConfig:
    """Configuration for the worker process.

    Attributes:
        database_url: PostgreSQL connection URL (asyncpg format).
        worker_id: Unique identifier for this worker instance.
        poll_interval: Seconds between job queue polls when idle.
        batch_size: Maximum jobs to process per poll cycle (future use).
        queues: List of queue names to process. Empty means all queues.
        job_types: List of job types to process. Empty means all types.
        stale_job_threshold_seconds: How long before a running job is considered stale.
        shutdown_timeout: Seconds to wait for graceful shutdown.
        pool_size: Database connection pool size.
    """

    database_url: str
    worker_id: str = field(default_factory=lambda: f"worker-{uuid.uuid4().hex[:8]}")
    poll_interval: float = 1.0
    batch_size: int = 10
    queues: list[str] = field(default_factory=lambda: ["default"])
    job_types: list[str] = field(default_factory=list)
    stale_job_threshold_seconds: int = 600
    shutdown_timeout: float = 30.0
    pool_size: int = 5


class Worker:
    """Background job worker that processes jobs from the PostgreSQL queue.

    The worker uses SELECT ... FOR UPDATE SKIP LOCKED to safely claim jobs
    without race conditions. Multiple workers can run concurrently.

    Example:
        config = WorkerConfig(
            database_url="postgresql+asyncpg://user:pass@localhost/qerds"
        )
        worker = Worker(config)
        await worker.start()
    """

    def __init__(self, config: WorkerConfig) -> None:
        """Initialize the worker.

        Args:
            config: Worker configuration settings.
        """
        self.config = config
        self._shutdown_event = asyncio.Event()
        self._current_job: Job | None = None
        self._handlers: dict[str, JobHandler] = {}
        self._engine = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
        self._started_at: datetime | None = None
        self._jobs_processed = 0
        self._jobs_failed = 0

    def register_handler(self, job_type: str | JobType, handler: JobHandler) -> None:
        """Register a handler for a specific job type.

        Args:
            job_type: The job type string or JobType enum.
            handler: Async function that processes the job.
        """
        type_str = job_type.value if isinstance(job_type, JobType) else job_type
        self._handlers[type_str] = handler
        logger.debug("Registered handler for job_type=%s", type_str)

    async def start(self) -> None:
        """Start the worker and begin processing jobs.

        This method runs until shutdown is requested via signal or stop().
        """
        self._started_at = datetime.now(UTC)
        logger.info(
            "Worker starting: worker_id=%s, queues=%s",
            self.config.worker_id,
            self.config.queues,
        )

        # Create database engine and session factory
        self._engine = create_async_engine(
            self.config.database_url,
            pool_size=self.config.pool_size,
            pool_pre_ping=True,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            expire_on_commit=False,
        )

        try:
            # Run the main processing loop
            await self._run_loop()
        finally:
            # Cleanup
            if self._engine:
                await self._engine.dispose()

            logger.info(
                "Worker stopped: worker_id=%s, processed=%d, failed=%d, uptime=%s",
                self.config.worker_id,
                self._jobs_processed,
                self._jobs_failed,
                self._get_uptime(),
            )

    async def stop(self) -> None:
        """Request graceful shutdown of the worker."""
        logger.info("Worker shutdown requested: worker_id=%s", self.config.worker_id)
        self._shutdown_event.set()

    async def _run_loop(self) -> None:
        """Main processing loop that polls for and processes jobs."""
        while not self._shutdown_event.is_set():
            try:
                # Process jobs for each configured queue
                for queue in self.config.queues:
                    if self._shutdown_event.is_set():
                        break
                    await self._process_queue(queue)

                # Periodically clean up stale jobs
                if not self._shutdown_event.is_set():
                    await self._cleanup_stale_jobs()

                # Wait before next poll cycle (uses wait_for to allow shutdown)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.config.poll_interval,
                    )

            except Exception as e:
                # Log error but continue running
                logger.exception("Error in worker loop: %s", e)
                # Brief pause before retrying to avoid tight error loops
                await asyncio.sleep(1.0)

    async def _process_queue(self, queue: str) -> None:
        """Process available jobs from a specific queue.

        Args:
            queue: The queue name to process.
        """
        async with self._session_factory() as session:
            job_queue = JobQueueService(session)

            # Determine which job types to process
            job_types = self.config.job_types if self.config.job_types else None

            # Claim the next available job
            job = await job_queue.claim_job(
                worker_id=self.config.worker_id,
                queue=queue,
                job_types=job_types,
            )

            if job is None:
                return

            self._current_job = job
            logger.info(
                "Processing job: job_id=%s, job_type=%s, attempt=%d/%d",
                job.job_id,
                job.job_type,
                job.attempts,
                job.max_attempts,
            )

            try:
                # Look up the handler for this job type
                handler = self._handlers.get(job.job_type)
                if handler is None:
                    error_msg = f"No handler registered for job_type={job.job_type}"
                    logger.error(error_msg)
                    await job_queue.fail_job(job.job_id, error_msg)
                    await session.commit()
                    self._jobs_failed += 1
                    return

                # Execute the handler
                result = await handler(session, job)

                # Mark job as completed
                await job_queue.complete_job(job.job_id, result)
                await session.commit()
                self._jobs_processed += 1

                logger.info(
                    "Job completed: job_id=%s, job_type=%s",
                    job.job_id,
                    job.job_type,
                )

            except Exception as e:
                # Handle job failure
                logger.exception(
                    "Job failed: job_id=%s, job_type=%s, error=%s",
                    job.job_id,
                    job.job_type,
                    e,
                )
                await session.rollback()

                # Create a new session for the failure update
                async with self._session_factory() as fail_session:
                    fail_queue = JobQueueService(fail_session)
                    will_retry = await fail_queue.fail_job(job.job_id, str(e))
                    await fail_session.commit()

                    if will_retry:
                        logger.info("Job scheduled for retry: job_id=%s", job.job_id)
                    else:
                        logger.warning("Job dead-lettered: job_id=%s", job.job_id)
                        self._jobs_failed += 1

            finally:
                self._current_job = None

    async def _cleanup_stale_jobs(self) -> None:
        """Periodically clean up jobs that have been running too long."""
        async with self._session_factory() as session:
            job_queue = JobQueueService(session)
            count = await job_queue.cleanup_stale_jobs(
                stale_threshold_seconds=self.config.stale_job_threshold_seconds
            )
            if count > 0:
                await session.commit()
                logger.warning("Reset %d stale jobs", count)

    def _get_uptime(self) -> str:
        """Calculate worker uptime as a human-readable string."""
        if self._started_at is None:
            return "0s"
        delta = datetime.now(UTC) - self._started_at
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"


# Global shutdown event for signal handlers
_shutdown_event: asyncio.Event | None = None


def _handle_shutdown(signum: int, _frame: object) -> None:
    """Handle shutdown signals gracefully."""
    logger.info("Shutdown signal received (signal=%d)", signum)
    if _shutdown_event is not None:
        # Set the event in a thread-safe manner
        _shutdown_event.get_loop().call_soon_threadsafe(_shutdown_event.set)


def _get_config_from_env() -> WorkerConfig:
    """Build WorkerConfig from environment variables.

    Environment variables:
        DATABASE_URL: PostgreSQL connection URL (required)
        WORKER_ID: Unique worker identifier (optional, auto-generated if not set)
        WORKER_POLL_INTERVAL: Seconds between polls (default: 1.0)
        WORKER_QUEUES: Comma-separated list of queues (default: "default")
        WORKER_JOB_TYPES: Comma-separated list of job types (default: all)
        WORKER_STALE_THRESHOLD: Seconds before job considered stale (default: 600)
        WORKER_SHUTDOWN_TIMEOUT: Seconds for graceful shutdown (default: 30)
        WORKER_POOL_SIZE: Database connection pool size (default: 5)

    Returns:
        WorkerConfig populated from environment.

    Raises:
        ValueError: If required environment variables are missing.
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        msg = "DATABASE_URL environment variable is required"
        raise ValueError(msg)

    # Convert sync URL to async if needed
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    worker_id = os.environ.get("WORKER_ID", f"worker-{uuid.uuid4().hex[:8]}")
    poll_interval = float(os.environ.get("WORKER_POLL_INTERVAL", "1.0"))
    queues_str = os.environ.get("WORKER_QUEUES", "default")
    queues = [q.strip() for q in queues_str.split(",") if q.strip()]
    job_types_str = os.environ.get("WORKER_JOB_TYPES", "")
    job_types = [j.strip() for j in job_types_str.split(",") if j.strip()]
    stale_threshold = int(os.environ.get("WORKER_STALE_THRESHOLD", "600"))
    shutdown_timeout = float(os.environ.get("WORKER_SHUTDOWN_TIMEOUT", "30"))
    pool_size = int(os.environ.get("WORKER_POOL_SIZE", "5"))

    return WorkerConfig(
        database_url=database_url,
        worker_id=worker_id,
        poll_interval=poll_interval,
        queues=queues,
        job_types=job_types,
        stale_job_threshold_seconds=stale_threshold,
        shutdown_timeout=shutdown_timeout,
        pool_size=pool_size,
    )


def _register_default_handlers(worker: Worker) -> None:
    """Register the default job handlers.

    Args:
        worker: The worker instance to register handlers on.
    """
    # Import handlers here to avoid circular imports
    from qerds.worker.handlers.bounce import process_bounce_handler
    from qerds.worker.handlers.checkpoint import seal_checkpoint_handler
    from qerds.worker.handlers.expiry import check_expiry_handler
    from qerds.worker.handlers.notification import send_notification_handler
    from qerds.worker.handlers.retention import enforce_retention_handler

    # Register all handlers
    worker.register_handler(JobType.NOTIFICATION_SEND, send_notification_handler)
    worker.register_handler(JobType.DELIVERY_EXPIRE, check_expiry_handler)
    worker.register_handler(JobType.LOG_CHECKPOINT, seal_checkpoint_handler)
    worker.register_handler(JobType.RETENTION_ENFORCE, enforce_retention_handler)
    worker.register_handler("process_bounce", process_bounce_handler)


async def _async_main(shutdown_event: asyncio.Event) -> None:
    """Async entry point for the worker.

    Args:
        shutdown_event: Event to signal shutdown request.
    """
    config = _get_config_from_env()
    worker = Worker(config)
    _register_default_handlers(worker)

    # Create a task for the worker
    worker_task = asyncio.create_task(worker.start())

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Request graceful shutdown
    await worker.stop()

    # Wait for worker to finish (with timeout)
    try:
        await asyncio.wait_for(worker_task, timeout=config.shutdown_timeout)
    except TimeoutError:
        logger.warning("Worker did not stop within timeout, forcing shutdown")
        worker_task.cancel()


def run() -> NoReturn:
    """Run the worker process.

    This is the main entry point for the worker. It:
    - Sets up logging
    - Registers signal handlers for graceful shutdown
    - Loads configuration from environment variables
    - Runs the async worker loop
    """
    global _shutdown_event

    # Set up logging
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    logger.info("QERDS Worker starting...")

    async def _run_with_event() -> None:
        """Create event loop context and run main."""
        global _shutdown_event
        _shutdown_event = asyncio.Event()
        await _async_main(_shutdown_event)

    try:
        asyncio.run(_run_with_event())
    except KeyboardInterrupt:
        logger.info("Worker interrupted")
    except Exception as e:
        logger.exception("Worker failed: %s", e)
        sys.exit(1)

    logger.info("QERDS Worker shutdown complete")
    sys.exit(0)


if __name__ == "__main__":
    run()
