"""Tests for the QERDS background worker service.

Tests cover:
- Worker initialization and configuration
- Handler registration
- Job processing flow
- Error handling and retry logic
- Graceful shutdown
- Scheduler functionality
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qerds.db.models.base import JobStatus
from qerds.services.job_queue import JobType
from qerds.worker.main import Worker, WorkerConfig, _get_config_from_env
from qerds.worker.scheduler import DEFAULT_SCHEDULES, ScheduledJob, Scheduler


class TestWorkerConfig:
    """Tests for WorkerConfig dataclass."""

    def test_default_config(self):
        """Test WorkerConfig with minimal required fields."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")

        assert config.database_url == "postgresql+asyncpg://localhost/test"
        assert config.poll_interval == 1.0
        assert config.batch_size == 10
        assert config.queues == ["default"]
        assert config.job_types == []
        assert config.stale_job_threshold_seconds == 600
        assert config.shutdown_timeout == 30.0
        assert config.pool_size == 5

    def test_worker_id_auto_generated(self):
        """Test that worker_id is auto-generated if not provided."""
        config1 = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        config2 = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")

        assert config1.worker_id.startswith("worker-")
        assert config2.worker_id.startswith("worker-")
        # Auto-generated IDs should be unique
        assert config1.worker_id != config2.worker_id

    def test_custom_config(self):
        """Test WorkerConfig with custom values."""
        config = WorkerConfig(
            database_url="postgresql+asyncpg://localhost/test",
            worker_id="custom-worker",
            poll_interval=2.5,
            batch_size=50,
            queues=["high", "default", "low"],
            job_types=["notification_send", "delivery_expire"],
            stale_job_threshold_seconds=1200,
            shutdown_timeout=60.0,
            pool_size=10,
        )

        assert config.worker_id == "custom-worker"
        assert config.poll_interval == 2.5
        assert config.batch_size == 50
        assert config.queues == ["high", "default", "low"]
        assert config.job_types == ["notification_send", "delivery_expire"]
        assert config.stale_job_threshold_seconds == 1200
        assert config.shutdown_timeout == 60.0
        assert config.pool_size == 10


class TestWorkerInit:
    """Tests for Worker initialization."""

    def test_worker_init(self):
        """Test Worker initializes with config."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)

        assert worker.config is config
        assert worker._handlers == {}
        assert worker._jobs_processed == 0
        assert worker._jobs_failed == 0
        assert worker._started_at is None

    def test_register_handler_with_string(self):
        """Test registering a handler with string job type."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)

        async def my_handler(session, job):
            return {"done": True}

        worker.register_handler("my_job", my_handler)

        assert "my_job" in worker._handlers
        assert worker._handlers["my_job"] is my_handler

    def test_register_handler_with_enum(self):
        """Test registering a handler with JobType enum."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)

        async def notification_handler(session, job):
            return {"sent": True}

        worker.register_handler(JobType.NOTIFICATION_SEND, notification_handler)

        assert "notification_send" in worker._handlers
        assert worker._handlers["notification_send"] is notification_handler


class TestWorkerProcessing:
    """Tests for Worker job processing."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock config for testing."""
        return WorkerConfig(
            database_url="postgresql+asyncpg://localhost/test",
            worker_id="test-worker",
            poll_interval=0.1,
        )

    @pytest.fixture
    def mock_job(self):
        """Create a mock job for testing."""
        job = MagicMock()
        job.job_id = uuid.uuid4()
        job.job_type = "test_job"
        job.status = JobStatus.RUNNING
        job.attempts = 1
        job.max_attempts = 3
        job.payload_json = {"key": "value"}
        return job

    @pytest.mark.asyncio
    async def test_process_queue_no_jobs(self, mock_config):
        """Test processing when no jobs are available."""
        worker = Worker(mock_config)

        # Mock session and job queue
        mock_session = AsyncMock()
        mock_job_queue = AsyncMock()
        mock_job_queue.claim_job.return_value = None

        # Mock session factory
        worker._session_factory = MagicMock()
        worker._session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        worker._session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("qerds.worker.main.JobQueueService", return_value=mock_job_queue):
            await worker._process_queue("default")

        # Should not have processed any jobs
        assert worker._jobs_processed == 0

    @pytest.mark.asyncio
    async def test_process_queue_with_handler(self, mock_config, mock_job):
        """Test processing a job with a registered handler."""
        worker = Worker(mock_config)

        # Register handler
        handler_result = {"processed": True}
        mock_handler = AsyncMock(return_value=handler_result)
        worker.register_handler("test_job", mock_handler)

        # Mock session and job queue
        mock_session = AsyncMock()
        mock_job_queue = AsyncMock()
        mock_job_queue.claim_job.return_value = mock_job
        mock_job_queue.complete_job = AsyncMock()

        # Mock session factory
        worker._session_factory = MagicMock()
        worker._session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        worker._session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("qerds.worker.main.JobQueueService", return_value=mock_job_queue):
            await worker._process_queue("default")

        # Handler should have been called
        mock_handler.assert_called_once_with(mock_session, mock_job)

        # Job should be completed
        mock_job_queue.complete_job.assert_called_once_with(mock_job.job_id, handler_result)

        # Counter should be incremented
        assert worker._jobs_processed == 1

    @pytest.mark.asyncio
    async def test_process_queue_no_handler(self, mock_config, mock_job):
        """Test processing a job with no registered handler."""
        worker = Worker(mock_config)

        # Don't register any handler

        # Mock session and job queue
        mock_session = AsyncMock()
        mock_job_queue = AsyncMock()
        mock_job_queue.claim_job.return_value = mock_job
        mock_job_queue.fail_job = AsyncMock()

        # Mock session factory
        worker._session_factory = MagicMock()
        worker._session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        worker._session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("qerds.worker.main.JobQueueService", return_value=mock_job_queue):
            await worker._process_queue("default")

        # Job should be failed
        mock_job_queue.fail_job.assert_called_once()
        assert "No handler registered" in mock_job_queue.fail_job.call_args[0][1]

        # Failed counter should be incremented
        assert worker._jobs_failed == 1

    @pytest.mark.asyncio
    async def test_process_queue_handler_error(self, mock_config, mock_job):
        """Test processing when handler raises an exception."""
        worker = Worker(mock_config)

        # Register handler that raises an error
        mock_handler = AsyncMock(side_effect=RuntimeError("Handler failed"))
        worker.register_handler("test_job", mock_handler)

        # Mock session and job queue
        mock_session = AsyncMock()
        mock_job_queue = AsyncMock()
        mock_job_queue.claim_job.return_value = mock_job
        mock_job_queue.fail_job = AsyncMock(return_value=True)  # Will retry

        # Mock session factory
        worker._session_factory = MagicMock()
        worker._session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        worker._session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("qerds.worker.main.JobQueueService", return_value=mock_job_queue):
            await worker._process_queue("default")

        # Session should be rolled back
        mock_session.rollback.assert_called_once()

        # Jobs failed counter should not be incremented (will retry)
        assert worker._jobs_failed == 0


class TestWorkerShutdown:
    """Tests for Worker graceful shutdown."""

    @pytest.mark.asyncio
    async def test_stop_sets_shutdown_event(self):
        """Test that stop() sets the shutdown event."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)

        assert not worker._shutdown_event.is_set()

        await worker.stop()

        assert worker._shutdown_event.is_set()

    @pytest.mark.asyncio
    async def test_run_loop_exits_on_shutdown(self):
        """Test that the run loop exits when shutdown is requested."""
        config = WorkerConfig(
            database_url="postgresql+asyncpg://localhost/test",
            poll_interval=0.1,
        )
        worker = Worker(config)

        # Mock session factory to avoid DB calls
        mock_session = AsyncMock()
        mock_job_queue = AsyncMock()
        mock_job_queue.claim_job.return_value = None
        mock_job_queue.cleanup_stale_jobs.return_value = 0

        worker._session_factory = MagicMock()
        worker._session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        worker._session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        # Request shutdown after a short delay
        async def delayed_shutdown():
            await asyncio.sleep(0.2)
            await worker.stop()

        with patch("qerds.worker.main.JobQueueService", return_value=mock_job_queue):
            # Run both tasks concurrently
            loop_task = asyncio.create_task(worker._run_loop())
            shutdown_task = asyncio.create_task(delayed_shutdown())

            # Wait for both with timeout
            await asyncio.wait_for(
                asyncio.gather(loop_task, shutdown_task),
                timeout=2.0,
            )

        # Loop should have exited
        assert worker._shutdown_event.is_set()


class TestWorkerUptime:
    """Tests for Worker uptime calculation."""

    def test_uptime_not_started(self):
        """Test uptime when worker hasn't started."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)

        assert worker._get_uptime() == "0s"

    def test_uptime_seconds(self):
        """Test uptime in seconds."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)
        worker._started_at = datetime.now(UTC) - timedelta(seconds=45)

        uptime = worker._get_uptime()
        assert "45s" in uptime or "44s" in uptime  # Allow for timing variance

    def test_uptime_minutes(self):
        """Test uptime in minutes."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)
        worker._started_at = datetime.now(UTC) - timedelta(minutes=5, seconds=30)

        uptime = worker._get_uptime()
        assert "5m" in uptime
        assert "30s" in uptime

    def test_uptime_hours(self):
        """Test uptime in hours."""
        config = WorkerConfig(database_url="postgresql+asyncpg://localhost/test")
        worker = Worker(config)
        worker._started_at = datetime.now(UTC) - timedelta(hours=2, minutes=30, seconds=15)

        uptime = worker._get_uptime()
        assert "2h" in uptime
        assert "30m" in uptime


class TestConfigFromEnv:
    """Tests for _get_config_from_env function."""

    def test_missing_database_url(self):
        """Test that missing DATABASE_URL raises ValueError."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                _get_config_from_env()
            assert "DATABASE_URL" in str(exc_info.value)

    def test_converts_sync_url_to_async(self):
        """Test that sync PostgreSQL URL is converted to async."""
        env = {
            "DATABASE_URL": "postgresql://user:pass@localhost/db",
        }
        with patch.dict("os.environ", env, clear=True):
            config = _get_config_from_env()

        assert config.database_url.startswith("postgresql+asyncpg://")

    def test_parses_env_variables(self):
        """Test that all environment variables are parsed correctly."""
        env = {
            "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
            "WORKER_ID": "my-worker-001",
            "WORKER_POLL_INTERVAL": "2.5",
            "WORKER_QUEUES": "high,default,low",
            "WORKER_JOB_TYPES": "notification_send,delivery_expire",
            "WORKER_STALE_THRESHOLD": "900",
            "WORKER_SHUTDOWN_TIMEOUT": "45",
            "WORKER_POOL_SIZE": "8",
        }
        with patch.dict("os.environ", env, clear=True):
            config = _get_config_from_env()

        assert config.worker_id == "my-worker-001"
        assert config.poll_interval == 2.5
        assert config.queues == ["high", "default", "low"]
        assert config.job_types == ["notification_send", "delivery_expire"]
        assert config.stale_job_threshold_seconds == 900
        assert config.shutdown_timeout == 45.0
        assert config.pool_size == 8


class TestScheduledJob:
    """Tests for ScheduledJob dataclass."""

    def test_default_values(self):
        """Test ScheduledJob with default values."""
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
        )

        assert schedule.job_type == "test_job"
        assert schedule.interval == timedelta(hours=1)
        assert schedule.payload == {}
        assert schedule.queue == "default"
        assert schedule.priority == 100
        assert schedule.enabled is True
        assert schedule.last_scheduled is None

    def test_custom_values(self):
        """Test ScheduledJob with custom values."""
        schedule = ScheduledJob(
            job_type="my_job",
            interval=timedelta(minutes=30),
            payload={"key": "value"},
            queue="priority",
            priority=10,
            enabled=False,
        )

        assert schedule.job_type == "my_job"
        assert schedule.interval == timedelta(minutes=30)
        assert schedule.payload == {"key": "value"}
        assert schedule.queue == "priority"
        assert schedule.priority == 10
        assert schedule.enabled is False


class TestScheduler:
    """Tests for Scheduler class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        return AsyncMock()

    def test_add_schedule(self, mock_session):
        """Test adding a schedule."""
        scheduler = Scheduler(mock_session)
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
        )

        scheduler.add_schedule(schedule)

        assert len(scheduler._schedules) == 1
        assert scheduler._schedules[0] is schedule

    def test_add_default_schedules(self, mock_session):
        """Test adding default schedules."""
        scheduler = Scheduler(mock_session)

        scheduler.add_default_schedules()

        assert len(scheduler._schedules) == len(DEFAULT_SCHEDULES)

    def test_is_due_never_scheduled(self, mock_session):
        """Test _is_due returns True for never-scheduled job."""
        scheduler = Scheduler(mock_session)
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
            last_scheduled=None,
        )

        assert scheduler._is_due(schedule, datetime.now(UTC)) is True

    def test_is_due_after_interval(self, mock_session):
        """Test _is_due returns True after interval has passed."""
        scheduler = Scheduler(mock_session)
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
            last_scheduled=datetime.now(UTC) - timedelta(hours=2),
        )

        assert scheduler._is_due(schedule, datetime.now(UTC)) is True

    def test_is_due_before_interval(self, mock_session):
        """Test _is_due returns False before interval has passed."""
        scheduler = Scheduler(mock_session)
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
            last_scheduled=datetime.now(UTC) - timedelta(minutes=30),
        )

        assert scheduler._is_due(schedule, datetime.now(UTC)) is False

    @pytest.mark.asyncio
    async def test_tick_schedules_due_jobs(self, mock_session):
        """Test tick() schedules jobs that are due."""
        scheduler = Scheduler(mock_session)

        # Add a schedule that's due (never scheduled)
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
        )
        scheduler.add_schedule(schedule)

        # Mock job queue to return no pending jobs
        mock_job_queue = AsyncMock()
        mock_job_queue.enqueue = AsyncMock(return_value=uuid.uuid4())

        with patch.object(scheduler, "_has_pending_job", return_value=False):
            scheduler._job_queue = mock_job_queue
            scheduled = await scheduler.tick()

        assert "test_job" in scheduled
        mock_job_queue.enqueue.assert_called_once()
        assert schedule.last_scheduled is not None

    @pytest.mark.asyncio
    async def test_tick_skips_disabled_schedules(self, mock_session):
        """Test tick() skips disabled schedules."""
        scheduler = Scheduler(mock_session)

        # Add a disabled schedule
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
            enabled=False,
        )
        scheduler.add_schedule(schedule)

        mock_job_queue = AsyncMock()
        scheduler._job_queue = mock_job_queue

        scheduled = await scheduler.tick()

        assert scheduled == []
        mock_job_queue.enqueue.assert_not_called()

    @pytest.mark.asyncio
    async def test_tick_skips_if_pending_exists(self, mock_session):
        """Test tick() skips if pending job already exists."""
        scheduler = Scheduler(mock_session)

        # Add a schedule that's due
        schedule = ScheduledJob(
            job_type="test_job",
            interval=timedelta(hours=1),
        )
        scheduler.add_schedule(schedule)

        # Mock to indicate pending job exists
        mock_job_queue = AsyncMock()
        scheduler._job_queue = mock_job_queue

        with patch.object(scheduler, "_has_pending_job", return_value=True):
            scheduled = await scheduler.tick()

        assert scheduled == []
        mock_job_queue.enqueue.assert_not_called()


class TestDefaultSchedules:
    """Tests for default schedule definitions."""

    def test_expiry_schedule_exists(self):
        """Test that delivery expiry schedule is defined."""
        expiry_type = JobType.DELIVERY_EXPIRE.value
        expiry_schedules = [s for s in DEFAULT_SCHEDULES if s.job_type == expiry_type]
        assert len(expiry_schedules) == 1

        schedule = expiry_schedules[0]
        assert schedule.interval == timedelta(minutes=5)

    def test_checkpoint_schedule_exists(self):
        """Test that checkpoint schedule is defined."""
        checkpoint_type = JobType.LOG_CHECKPOINT.value
        checkpoint_schedules = [s for s in DEFAULT_SCHEDULES if s.job_type == checkpoint_type]
        assert len(checkpoint_schedules) == 1

        schedule = checkpoint_schedules[0]
        assert schedule.interval == timedelta(hours=1)

    def test_retention_schedule_exists(self):
        """Test that retention schedule is defined."""
        retention_type = JobType.RETENTION_ENFORCE.value
        retention_schedules = [s for s in DEFAULT_SCHEDULES if s.job_type == retention_type]
        assert len(retention_schedules) == 1

        schedule = retention_schedules[0]
        assert schedule.interval == timedelta(hours=24)
        # Retention should be low priority
        assert schedule.priority > 100
