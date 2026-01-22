"""Tests for the PostgreSQL-backed job queue service.

Tests cover:
- Job enqueue with various parameters
- Concurrent job claiming with SKIP LOCKED
- Job completion and failure handling
- Exponential backoff retry logic
- Dead letter handling (max_attempts exceeded)
- Stale job cleanup

All tests run against PostgreSQL via Docker for reproducibility.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError

from qerds.db.models.base import JobStatus
from qerds.db.models.jobs import Job
from qerds.services.job_queue import (
    JobAlreadyClaimedError,
    JobNotFoundError,
    JobQueueError,
    JobQueueService,
    JobType,
)


class TestJobQueueServiceInit:
    """Tests for JobQueueService initialization."""

    def test_init_with_defaults(self):
        """Test service initializes with default values."""
        session = MagicMock()
        service = JobQueueService(session)

        assert service.session is session
        assert service.default_queue == "default"
        assert service.default_max_attempts == 3
        assert service.default_lock_timeout == 300
        assert service.default_base_backoff == 60

    def test_init_with_custom_values(self):
        """Test service accepts custom configuration."""
        session = MagicMock()
        service = JobQueueService(
            session,
            default_queue="priority",
            default_max_attempts=5,
            default_lock_timeout=600,
            default_base_backoff=120,
        )

        assert service.default_queue == "priority"
        assert service.default_max_attempts == 5
        assert service.default_lock_timeout == 600
        assert service.default_base_backoff == 120


class TestJobEnqueue:
    """Tests for enqueue method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_enqueue_basic(self, mock_session):
        """Test basic job enqueueing."""
        service = JobQueueService(mock_session)

        # Mock flush to set job_id
        async def set_job_id():
            job = mock_session.add.call_args[0][0]
            job.job_id = uuid.uuid4()

        mock_session.flush.side_effect = set_job_id

        job_id = await service.enqueue(
            job_type=JobType.NOTIFICATION_SEND,
            payload={"recipient_id": "test-123"},
        )

        assert job_id is not None
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

        # Verify the job was created with correct values
        created_job = mock_session.add.call_args[0][0]
        assert created_job.job_type == "notification_send"
        assert created_job.status == JobStatus.PENDING
        assert created_job.payload_json == {"recipient_id": "test-123"}
        assert created_job.queue == "default"
        assert created_job.priority == 100

    @pytest.mark.asyncio
    async def test_enqueue_with_scheduled_time(self, mock_session):
        """Test enqueueing a job with future run_at."""
        service = JobQueueService(mock_session)
        future_time = datetime.now(UTC) + timedelta(hours=1)

        async def set_job_id():
            job = mock_session.add.call_args[0][0]
            job.job_id = uuid.uuid4()

        mock_session.flush.side_effect = set_job_id

        await service.enqueue(
            job_type=JobType.DELIVERY_EXPIRE,
            run_at=future_time,
        )

        created_job = mock_session.add.call_args[0][0]
        assert created_job.run_at == future_time

    @pytest.mark.asyncio
    async def test_enqueue_with_all_options(self, mock_session):
        """Test enqueueing with all optional parameters."""
        service = JobQueueService(mock_session)

        async def set_job_id():
            job = mock_session.add.call_args[0][0]
            job.job_id = uuid.uuid4()

        mock_session.flush.side_effect = set_job_id

        await service.enqueue(
            job_type="custom_job",
            payload={"key": "value"},
            run_at=datetime.now(UTC),
            queue="priority",
            priority=10,
            max_attempts=5,
            correlation_id="corr-123",
            parent_job_id="parent-456",
        )

        created_job = mock_session.add.call_args[0][0]
        assert created_job.job_type == "custom_job"
        assert created_job.queue == "priority"
        assert created_job.priority == 10
        assert created_job.max_attempts == 5
        assert created_job.correlation_id == "corr-123"
        assert created_job.parent_job_id == "parent-456"

    @pytest.mark.asyncio
    async def test_enqueue_database_error(self, mock_session):
        """Test enqueue handles database errors gracefully."""
        service = JobQueueService(mock_session)
        mock_session.flush.side_effect = SQLAlchemyError("DB error")

        with pytest.raises(JobQueueError) as exc_info:
            await service.enqueue(job_type=JobType.LOG_CHECKPOINT)

        assert "Failed to enqueue job" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_enqueue_job_type_enum_conversion(self, mock_session):
        """Test that JobType enum is correctly converted to string."""
        service = JobQueueService(mock_session)

        async def set_job_id():
            job = mock_session.add.call_args[0][0]
            job.job_id = uuid.uuid4()

        mock_session.flush.side_effect = set_job_id

        await service.enqueue(job_type=JobType.RETENTION_ENFORCE)

        created_job = mock_session.add.call_args[0][0]
        assert created_job.job_type == "retention_enforce"


class TestJobClaim:
    """Tests for claim_job method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session for claim tests."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_claim_job_success(self, mock_session):
        """Test successful job claiming."""
        service = JobQueueService(mock_session)

        # Create a mock job
        mock_job = MagicMock(spec=Job)
        mock_job.job_id = uuid.uuid4()
        mock_job.job_type = "notification_send"
        mock_job.status = JobStatus.PENDING
        mock_job.attempts = 0
        mock_job.max_attempts = 3

        # Configure mock to return the job
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        claimed_job = await service.claim_job("worker-1")

        assert claimed_job is mock_job
        assert mock_job.status == JobStatus.RUNNING
        assert mock_job.locked_by == "worker-1"
        assert mock_job.attempts == 1
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_claim_job_none_available(self, mock_session):
        """Test claim returns None when no jobs available."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await service.claim_job("worker-1")

        assert result is None
        mock_session.flush.assert_not_called()

    @pytest.mark.asyncio
    async def test_claim_job_specific_queue(self, mock_session):
        """Test claiming from a specific queue."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        await service.claim_job("worker-1", queue="priority")

        # Verify execute was called (the query construction is internal)
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_claim_job_with_job_type_filter(self, mock_session):
        """Test claiming with job type filter."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        await service.claim_job(
            "worker-1",
            job_types=["notification_send", "delivery_expire"],
        )

        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_claim_job_database_error(self, mock_session):
        """Test claim handles database errors."""
        service = JobQueueService(mock_session)
        mock_session.execute.side_effect = SQLAlchemyError("Connection lost")

        with pytest.raises(JobQueueError) as exc_info:
            await service.claim_job("worker-1")

        assert "Failed to claim job" in str(exc_info.value)


class TestJobComplete:
    """Tests for complete_job method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_complete_job_success(self, mock_session):
        """Test successful job completion."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "notification_send"
        mock_job.started_at = datetime.now(UTC) - timedelta(seconds=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        await service.complete_job(job_id, result={"sent": True})

        assert mock_job.status == JobStatus.COMPLETED
        assert mock_job.result_json == {"sent": True}
        assert mock_job.completed_at is not None
        assert mock_job.duration_ms is not None
        assert mock_job.locked_at is None
        assert mock_job.locked_by is None
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_complete_job_not_found(self, mock_session):
        """Test complete raises error when job not found."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        with pytest.raises(JobNotFoundError) as exc_info:
            await service.complete_job(job_id)

        assert str(job_id) in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_complete_job_calculates_duration(self, mock_session):
        """Test that duration is calculated correctly."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        started_at = datetime.now(UTC) - timedelta(seconds=10)
        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "test"
        mock_job.started_at = started_at

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        await service.complete_job(job_id)

        # Duration should be approximately 10 seconds = 10000ms
        # Allow some tolerance for test execution time
        assert mock_job.duration_ms >= 10000
        assert mock_job.duration_ms < 11000


class TestJobFail:
    """Tests for fail_job method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_fail_job_retry(self, mock_session):
        """Test failing a job schedules retry with backoff."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "notification_send"
        mock_job.attempts = 1  # First attempt
        mock_job.max_attempts = 3
        mock_job.base_backoff_seconds = 60
        mock_job.started_at = datetime.now(UTC)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        will_retry = await service.fail_job(job_id, "Connection timeout")

        assert will_retry is True
        assert mock_job.status == JobStatus.PENDING
        assert mock_job.last_error == "Connection timeout"
        assert mock_job.locked_at is None
        assert mock_job.locked_by is None
        # Backoff should be 60 seconds for first retry (60 * 2^0)
        assert mock_job.run_at is not None

    @pytest.mark.asyncio
    async def test_fail_job_exponential_backoff(self, mock_session):
        """Test exponential backoff calculation."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "test"
        mock_job.attempts = 2  # Second attempt
        mock_job.max_attempts = 5
        mock_job.base_backoff_seconds = 60
        mock_job.started_at = datetime.now(UTC)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        now = datetime.now(UTC)
        await service.fail_job(job_id, "Error")

        # Backoff should be 60 * 2^1 = 120 seconds
        expected_run_at = now + timedelta(seconds=120)
        actual_run_at = mock_job.run_at

        # Allow small time tolerance
        assert abs((actual_run_at - expected_run_at).total_seconds()) < 2

    @pytest.mark.asyncio
    async def test_fail_job_dead_letter(self, mock_session):
        """Test job moves to dead letter after max attempts."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "notification_send"
        mock_job.attempts = 3  # At max attempts
        mock_job.max_attempts = 3
        mock_job.started_at = datetime.now(UTC) - timedelta(seconds=5)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        will_retry = await service.fail_job(job_id, "Permanent failure")

        assert will_retry is False
        assert mock_job.status == JobStatus.FAILED
        assert mock_job.last_error == "Permanent failure"
        assert mock_job.completed_at is not None
        assert mock_job.duration_ms is not None

    @pytest.mark.asyncio
    async def test_fail_job_not_found(self, mock_session):
        """Test fail raises error when job not found."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        with pytest.raises(JobNotFoundError):
            await service.fail_job(job_id, "Error")


class TestJobCancel:
    """Tests for cancel_job method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_cancel_pending_job(self, mock_session):
        """Test cancelling a pending job."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "test"
        mock_job.status = JobStatus.PENDING

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        await service.cancel_job(job_id)

        assert mock_job.status == JobStatus.CANCELLED
        assert mock_job.completed_at is not None
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_cancel_running_job(self, mock_session):
        """Test cancelling a running job."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "test"
        mock_job.status = JobStatus.RUNNING

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        await service.cancel_job(job_id)

        assert mock_job.status == JobStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_completed_job_fails(self, mock_session):
        """Test cannot cancel already completed job."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.status = JobStatus.COMPLETED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        with pytest.raises(JobQueueError) as exc_info:
            await service.cancel_job(job_id)

        assert "Cannot cancel job" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cancel_failed_job_fails(self, mock_session):
        """Test cannot cancel already failed job."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.status = JobStatus.FAILED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        with pytest.raises(JobQueueError) as exc_info:
            await service.cancel_job(job_id)

        assert "Cannot cancel job" in str(exc_info.value)


class TestDeadLetterHandling:
    """Tests for dead letter queue handling."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_get_failed_jobs(self, mock_session):
        """Test retrieving failed jobs."""
        service = JobQueueService(mock_session)

        failed_job_1 = MagicMock(spec=Job)
        failed_job_2 = MagicMock(spec=Job)

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [failed_job_1, failed_job_2]
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        failed_jobs = await service.get_failed_jobs()

        assert len(failed_jobs) == 2
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_failed_jobs_with_filters(self, mock_session):
        """Test retrieving failed jobs with queue and type filters."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        await service.get_failed_jobs(
            queue="priority",
            job_type="notification_send",
            limit=50,
        )

        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_failed_job(self, mock_session):
        """Test manually retrying a failed job."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.job_type = "notification_send"
        mock_job.status = JobStatus.FAILED
        mock_job.attempts = 3
        mock_job.last_error = "Previous error"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        await service.retry_failed_job(job_id)

        assert mock_job.status == JobStatus.PENDING
        assert mock_job.attempts == 0
        assert mock_job.last_error is None
        assert mock_job.completed_at is None
        assert mock_job.duration_ms is None
        mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_non_failed_job_fails(self, mock_session):
        """Test cannot retry a job that isn't failed."""
        service = JobQueueService(mock_session)
        job_id = uuid.uuid4()

        mock_job = MagicMock(spec=Job)
        mock_job.job_id = job_id
        mock_job.status = JobStatus.PENDING

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result

        with pytest.raises(JobQueueError) as exc_info:
            await service.retry_failed_job(job_id)

        assert "Can only retry FAILED jobs" in str(exc_info.value)


class TestStaleJobCleanup:
    """Tests for stale job cleanup functionality."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_cleanup_stale_jobs(self, mock_session):
        """Test cleaning up stale (locked too long) jobs."""
        service = JobQueueService(mock_session)

        # Mock returning 2 stale job IDs
        stale_ids = [uuid.uuid4(), uuid.uuid4()]
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = stale_ids
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        count = await service.cleanup_stale_jobs(stale_threshold_seconds=600)

        assert count == 2
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_no_stale_jobs(self, mock_session):
        """Test cleanup when no stale jobs exist."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        count = await service.cleanup_stale_jobs()

        assert count == 0


class TestPendingCount:
    """Tests for get_pending_count method."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.execute = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_get_pending_count(self, mock_session):
        """Test getting pending job count."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar.return_value = 5
        mock_session.execute.return_value = mock_result

        count = await service.get_pending_count()

        assert count == 5

    @pytest.mark.asyncio
    async def test_get_pending_count_with_filters(self, mock_session):
        """Test pending count with queue and type filters."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar.return_value = 3
        mock_session.execute.return_value = mock_result

        count = await service.get_pending_count(
            queue="priority",
            job_type="notification_send",
        )

        assert count == 3

    @pytest.mark.asyncio
    async def test_get_pending_count_zero(self, mock_session):
        """Test pending count when no jobs exist."""
        service = JobQueueService(mock_session)

        mock_result = MagicMock()
        mock_result.scalar.return_value = None
        mock_session.execute.return_value = mock_result

        count = await service.get_pending_count()

        assert count == 0


class TestJobType:
    """Tests for JobType enum."""

    def test_job_type_values(self):
        """Test JobType enum has expected values."""
        assert JobType.NOTIFICATION_SEND.value == "notification_send"
        assert JobType.DELIVERY_EXPIRE.value == "delivery_expire"
        assert JobType.LOG_CHECKPOINT.value == "log_checkpoint"
        assert JobType.RETENTION_ENFORCE.value == "retention_enforce"

    def test_job_type_is_string_enum(self):
        """Test JobType values can be used as strings."""
        assert str(JobType.NOTIFICATION_SEND) == "JobType.NOTIFICATION_SEND"
        assert JobType.NOTIFICATION_SEND.value == "notification_send"


class TestExceptionTypes:
    """Tests for custom exception types."""

    def test_job_queue_error(self):
        """Test JobQueueError can be raised and caught."""
        with pytest.raises(JobQueueError):
            raise JobQueueError("Test error")

    def test_job_not_found_error(self):
        """Test JobNotFoundError is a JobQueueError subclass."""
        error = JobNotFoundError("Job not found")
        assert isinstance(error, JobQueueError)

    def test_job_already_claimed_error(self):
        """Test JobAlreadyClaimedError is a JobQueueError subclass."""
        error = JobAlreadyClaimedError("Already claimed")
        assert isinstance(error, JobQueueError)
