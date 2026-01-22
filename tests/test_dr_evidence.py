"""Tests for DR (Disaster Recovery) Evidence Service.

Tests cover:
- Recording backup execution evidence
- Recording restore test evidence
- Recording DR drill evidence
- RPO/RTO measurement and compliance tracking
- Evidence record retrieval and listing
- Summary statistics generation
- Audit pack integration

Run with: docker compose exec qerds-api pytest tests/test_dr_evidence.py -v
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from qerds.services.dr_evidence import (
    BackupScope,
    DREvidenceConfig,
    DREvidenceNotFoundError,
    DREvidenceOutcome,
    DREvidenceService,
    DREvidenceSummary,
    DREvidenceType,
    RPOTarget,
    RTOTarget,
)

# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    return MagicMock()


@pytest.fixture
def mock_object_store():
    """Create a mock object store client."""
    store = MagicMock()
    store.ensure_bucket = MagicMock()
    store.upload = MagicMock()
    return store


@pytest.fixture
def dr_config():
    """Create DR evidence configuration."""
    return DREvidenceConfig(
        evidence_bucket="test-dr-evidence",
        storage_prefix="dr-evidence/",
        default_rpo_minutes=60,
        default_rto_minutes=240,
    )


@pytest.fixture
def dr_service(mock_db_session, mock_object_store, dr_config):
    """Create a DR evidence service instance."""
    return DREvidenceService(mock_db_session, mock_object_store, dr_config)


# -----------------------------------------------------------------------------
# Data Class Tests
# -----------------------------------------------------------------------------


class TestDataClasses:
    """Tests for DR evidence data classes."""

    def test_backup_scope_defaults(self):
        """Test BackupScope has correct defaults."""
        scope = BackupScope()
        assert scope.postgresql is True
        assert scope.object_store is True
        assert scope.audit_logs is True
        assert scope.config is True

    def test_backup_scope_to_dict(self):
        """Test BackupScope serialization."""
        scope = BackupScope(postgresql=True, object_store=False)
        result = scope.to_dict()
        assert result["postgresql"] is True
        assert result["object_store"] is False

    def test_backup_scope_from_dict(self):
        """Test BackupScope deserialization."""
        data = {"postgresql": True, "object_store": False, "audit_logs": True, "config": False}
        scope = BackupScope.from_dict(data)
        assert scope.postgresql is True
        assert scope.object_store is False
        assert scope.audit_logs is True
        assert scope.config is False

    def test_rpo_target_serialization(self):
        """Test RPOTarget to_dict and from_dict."""
        rpo = RPOTarget(target_minutes=60, measured_minutes=45.5, meets_target=True)
        data = rpo.to_dict()
        assert data["target_minutes"] == 60
        assert data["measured_minutes"] == 45.5
        assert data["meets_target"] is True

        restored = RPOTarget.from_dict(data)
        assert restored.target_minutes == 60
        assert restored.measured_minutes == 45.5
        assert restored.meets_target is True

    def test_rto_target_serialization(self):
        """Test RTOTarget to_dict and from_dict."""
        rto = RTOTarget(target_minutes=240, measured_minutes=180.0, meets_target=True)
        data = rto.to_dict()
        assert data["target_minutes"] == 240
        assert data["measured_minutes"] == 180.0

        restored = RTOTarget.from_dict(data)
        assert restored.target_minutes == 240
        assert restored.measured_minutes == 180.0


class TestDREvidenceTypes:
    """Tests for DR evidence enums."""

    def test_evidence_type_values(self):
        """Test all evidence types are defined."""
        assert DREvidenceType.BACKUP_EXECUTION.value == "backup_execution"
        assert DREvidenceType.RESTORE_TEST.value == "restore_test"
        assert DREvidenceType.DR_DRILL.value == "dr_drill"
        assert DREvidenceType.RTO_MEASUREMENT.value == "rto_measurement"
        assert DREvidenceType.RPO_MEASUREMENT.value == "rpo_measurement"

    def test_outcome_values(self):
        """Test all outcome statuses are defined."""
        assert DREvidenceOutcome.SUCCESS.value == "success"
        assert DREvidenceOutcome.PARTIAL.value == "partial"
        assert DREvidenceOutcome.FAILURE.value == "failure"
        assert DREvidenceOutcome.IN_PROGRESS.value == "in_progress"


# -----------------------------------------------------------------------------
# Service Tests - Backup Execution
# -----------------------------------------------------------------------------


class TestBackupExecution:
    """Tests for recording backup execution evidence."""

    @pytest.mark.asyncio
    async def test_record_backup_execution_success(self, dr_service):
        """Test recording a successful backup execution."""
        record = await dr_service.record_backup_execution(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            backup_scope=BackupScope(postgresql=True, object_store=True),
            duration_seconds=120,
            summary="Scheduled daily backup completed successfully",
            details={"backup_id": "backup-20240115-001", "size_bytes": 1024000},
        )

        assert record.record_id is not None
        assert record.evidence_type == DREvidenceType.BACKUP_EXECUTION
        assert record.outcome == DREvidenceOutcome.SUCCESS
        assert record.executed_by == "operator-123"
        assert record.duration_seconds == 120
        assert record.backup_scope.postgresql is True
        assert record.summary == "Scheduled daily backup completed successfully"
        assert record.record_hash is not None

    @pytest.mark.asyncio
    async def test_record_backup_execution_failure(self, dr_service):
        """Test recording a failed backup execution."""
        record = await dr_service.record_backup_execution(
            executed_by="operator-456",
            outcome=DREvidenceOutcome.FAILURE,
            duration_seconds=30,
            summary="Backup failed due to disk space",
            details={"error": "ENOSPC", "available_bytes": 0},
        )

        assert record.outcome == DREvidenceOutcome.FAILURE
        assert record.details["error"] == "ENOSPC"

    @pytest.mark.asyncio
    async def test_record_backup_with_artifact(self, dr_service, mock_object_store):
        """Test recording backup execution with log artifact."""
        log_content = b"Backup started at 2024-01-15 00:00:00\nBackup completed."

        record = await dr_service.record_backup_execution(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup with log",
            artifact_data=log_content,
            artifact_filename="backup_log.txt",
        )

        assert len(record.artifact_refs) == 1
        mock_object_store.upload.assert_called_once()


# -----------------------------------------------------------------------------
# Service Tests - Restore Test
# -----------------------------------------------------------------------------


class TestRestoreTest:
    """Tests for recording restore test evidence."""

    @pytest.mark.asyncio
    async def test_record_restore_test_success(self, dr_service):
        """Test recording a successful restore test."""
        record = await dr_service.record_restore_test(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            backup_scope=BackupScope(postgresql=True, object_store=False),
            duration_seconds=300,
            summary="Quarterly restore test passed",
            details={
                "backup_id": "backup-20240115-001",
                "verified_tables": 42,
                "verified_rows": 100000,
            },
        )

        assert record.evidence_type == DREvidenceType.RESTORE_TEST
        assert record.outcome == DREvidenceOutcome.SUCCESS
        assert record.duration_seconds == 300
        assert record.details["verified_tables"] == 42

    @pytest.mark.asyncio
    async def test_record_restore_test_partial(self, dr_service):
        """Test recording a partial restore test."""
        record = await dr_service.record_restore_test(
            executed_by="operator-789",
            outcome=DREvidenceOutcome.PARTIAL,
            summary="Restore test passed with warnings",
            details={
                "warnings": ["Missing index on table X", "Sequence mismatch on table Y"],
            },
        )

        assert record.outcome == DREvidenceOutcome.PARTIAL
        assert len(record.details["warnings"]) == 2


# -----------------------------------------------------------------------------
# Service Tests - DR Drill
# -----------------------------------------------------------------------------


class TestDRDrill:
    """Tests for recording DR drill evidence."""

    @pytest.mark.asyncio
    async def test_record_dr_drill_success(self, dr_service):
        """Test recording a successful DR drill."""
        record = await dr_service.record_dr_drill(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            duration_seconds=14400,  # 4 hours
            rpo=RPOTarget(target_minutes=60, measured_minutes=45, meets_target=True),
            rto=RTOTarget(target_minutes=240, measured_minutes=180, meets_target=True),
            summary="Q1 2024 DR drill completed successfully",
            details={
                "drill_id": "dr-drill-2024q1",
                "participants": ["ops-team", "dev-team"],
                "runbook_version": "v2.3",
            },
        )

        assert record.evidence_type == DREvidenceType.DR_DRILL
        assert record.outcome == DREvidenceOutcome.SUCCESS
        assert record.rpo.measured_minutes == 45
        assert record.rpo.meets_target is True
        assert record.rto.measured_minutes == 180
        assert record.rto.meets_target is True

    @pytest.mark.asyncio
    async def test_record_dr_drill_rpo_failure(self, dr_service):
        """Test recording a DR drill where RPO target was not met."""
        record = await dr_service.record_dr_drill(
            executed_by="operator-456",
            outcome=DREvidenceOutcome.PARTIAL,
            duration_seconds=18000,
            rpo=RPOTarget(target_minutes=60, measured_minutes=90, meets_target=False),
            rto=RTOTarget(target_minutes=240, measured_minutes=200, meets_target=True),
            summary="DR drill completed but RPO exceeded",
            details={"issue": "Backup lag during failover"},
        )

        assert record.rpo.meets_target is False
        assert record.rto.meets_target is True

    @pytest.mark.asyncio
    async def test_record_dr_drill_uses_defaults(self, dr_service, dr_config):
        """Test that DR drill uses default RPO/RTO targets when not specified."""
        record = await dr_service.record_dr_drill(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="DR drill with default targets",
        )

        assert record.rpo.target_minutes == dr_config.default_rpo_minutes
        assert record.rto.target_minutes == dr_config.default_rto_minutes


# -----------------------------------------------------------------------------
# Service Tests - Retrieval
# -----------------------------------------------------------------------------


class TestRecordRetrieval:
    """Tests for retrieving DR evidence records."""

    @pytest.mark.asyncio
    async def test_get_record_success(self, dr_service):
        """Test getting an existing record by ID."""
        # First create a record
        created = await dr_service.record_backup_execution(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Test backup",
        )

        # Then retrieve it
        retrieved = await dr_service.get_record(created.record_id)

        assert retrieved.record_id == created.record_id
        assert retrieved.summary == "Test backup"

    @pytest.mark.asyncio
    async def test_get_record_not_found(self, dr_service):
        """Test getting a non-existent record raises error."""
        fake_id = uuid.uuid4()

        with pytest.raises(DREvidenceNotFoundError):
            await dr_service.get_record(fake_id)

    @pytest.mark.asyncio
    async def test_list_records_empty(self, dr_service):
        """Test listing records when none exist."""
        records = await dr_service.list_records()
        assert records == []

    @pytest.mark.asyncio
    async def test_list_records_filtered_by_type(self, dr_service):
        """Test listing records filtered by evidence type."""
        # Create mixed records
        await dr_service.record_backup_execution(
            executed_by="op-1",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup 1",
        )
        await dr_service.record_restore_test(
            executed_by="op-2",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Restore test 1",
        )
        await dr_service.record_backup_execution(
            executed_by="op-3",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup 2",
        )

        # Filter by backup execution
        backups = await dr_service.list_records(evidence_type=DREvidenceType.BACKUP_EXECUTION)
        assert len(backups) == 2

        # Filter by restore test
        restores = await dr_service.list_records(evidence_type=DREvidenceType.RESTORE_TEST)
        assert len(restores) == 1

    @pytest.mark.asyncio
    async def test_list_records_date_range(self, dr_service):
        """Test listing records within a date range."""
        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)
        tomorrow = now + timedelta(days=1)

        # Create a record with explicit executed_at
        await dr_service.record_backup_execution(
            executed_by="op-1",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Today's backup",
            executed_at=now,
        )

        # Should find the record
        records = await dr_service.list_records(
            start_date=yesterday,
            end_date=tomorrow,
        )
        assert len(records) == 1

        # Should not find the record (date range in future)
        future_start = now + timedelta(days=5)
        future_end = now + timedelta(days=10)
        records = await dr_service.list_records(
            start_date=future_start,
            end_date=future_end,
        )
        assert len(records) == 0


# -----------------------------------------------------------------------------
# Service Tests - Summary
# -----------------------------------------------------------------------------


class TestDRSummary:
    """Tests for DR evidence summary statistics."""

    @pytest.mark.asyncio
    async def test_summary_empty_period(self, dr_service):
        """Test summary for a period with no records."""
        now = datetime.now(UTC)
        start = now - timedelta(days=30)
        end = now

        summary = await dr_service.get_summary(start, end)

        assert summary.backup_count == 0
        assert summary.restore_test_count == 0
        assert summary.dr_drill_count == 0
        assert summary.success_rate == 0.0
        assert summary.last_successful_backup is None

    @pytest.mark.asyncio
    async def test_summary_with_records(self, dr_service):
        """Test summary with various records."""
        now = datetime.now(UTC)
        start = now - timedelta(days=30)
        end = now + timedelta(days=1)

        # Create some records
        await dr_service.record_backup_execution(
            executed_by="op-1",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup 1",
            executed_at=now - timedelta(days=1),
        )
        await dr_service.record_backup_execution(
            executed_by="op-2",
            outcome=DREvidenceOutcome.FAILURE,
            summary="Backup 2 (failed)",
            executed_at=now - timedelta(days=2),
        )
        await dr_service.record_restore_test(
            executed_by="op-3",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Restore test",
            executed_at=now - timedelta(days=3),
        )

        summary = await dr_service.get_summary(start, end)

        assert summary.backup_count == 2
        assert summary.restore_test_count == 1
        assert summary.dr_drill_count == 0
        assert summary.success_rate == pytest.approx(66.67, rel=0.1)
        assert summary.last_successful_backup is not None
        assert summary.last_restore_test is not None

    @pytest.mark.asyncio
    async def test_summary_rpo_rto_compliance(self, dr_service):
        """Test summary includes RPO/RTO compliance from DR drills."""
        now = datetime.now(UTC)
        start = now - timedelta(days=90)
        end = now + timedelta(days=1)

        # Create DR drill with passing metrics
        await dr_service.record_dr_drill(
            executed_by="op-1",
            outcome=DREvidenceOutcome.SUCCESS,
            rpo=RPOTarget(target_minutes=60, measured_minutes=30, meets_target=True),
            rto=RTOTarget(target_minutes=240, measured_minutes=120, meets_target=True),
            summary="Q1 drill",
            executed_at=now - timedelta(days=30),
        )

        summary = await dr_service.get_summary(start, end)

        assert summary.dr_drill_count == 1
        assert summary.rpo_compliance is True
        assert summary.rto_compliance is True


# -----------------------------------------------------------------------------
# Service Tests - Audit Pack Integration
# -----------------------------------------------------------------------------


class TestAuditPackIntegration:
    """Tests for audit pack integration."""

    @pytest.mark.asyncio
    async def test_get_records_for_audit_pack(self, dr_service):
        """Test getting records formatted for audit pack."""
        now = datetime.now(UTC)
        start = now - timedelta(days=30)
        end = now + timedelta(days=1)

        # Create some records
        await dr_service.record_backup_execution(
            executed_by="op-1",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup for audit",
            executed_at=now - timedelta(days=1),
        )
        await dr_service.record_dr_drill(
            executed_by="op-2",
            outcome=DREvidenceOutcome.SUCCESS,
            rpo=RPOTarget(target_minutes=60, measured_minutes=30, meets_target=True),
            rto=RTOTarget(target_minutes=240, measured_minutes=120, meets_target=True),
            summary="DR drill for audit",
            executed_at=now - timedelta(days=5),
        )

        # Get formatted records
        records = await dr_service.get_records_for_audit_pack(start, end)

        assert len(records) == 2
        assert all(isinstance(r, dict) for r in records)
        assert all("record_id" in r for r in records)
        assert all("evidence_type" in r for r in records)
        assert all("record_hash" in r for r in records)


# -----------------------------------------------------------------------------
# Service Tests - Record Integrity
# -----------------------------------------------------------------------------


class TestRecordIntegrity:
    """Tests for record integrity (hash computation)."""

    @pytest.mark.asyncio
    async def test_record_hash_is_deterministic(self, dr_service):
        """Test that record hash is computed consistently."""
        record = await dr_service.record_backup_execution(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Test backup",
        )

        # Hash should be a valid SHA-256 hex string
        assert len(record.record_hash) == 64
        assert all(c in "0123456789abcdef" for c in record.record_hash)

    @pytest.mark.asyncio
    async def test_different_records_have_different_hashes(self, dr_service):
        """Test that different records have different hashes."""
        record1 = await dr_service.record_backup_execution(
            executed_by="operator-1",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup 1",
        )
        record2 = await dr_service.record_backup_execution(
            executed_by="operator-2",
            outcome=DREvidenceOutcome.SUCCESS,
            summary="Backup 2",
        )

        assert record1.record_hash != record2.record_hash


# -----------------------------------------------------------------------------
# Service Tests - Record Serialization
# -----------------------------------------------------------------------------


class TestRecordSerialization:
    """Tests for record serialization."""

    @pytest.mark.asyncio
    async def test_record_to_dict(self, dr_service):
        """Test converting record to dictionary."""
        record = await dr_service.record_dr_drill(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            duration_seconds=3600,
            rpo=RPOTarget(target_minutes=60, measured_minutes=30, meets_target=True),
            rto=RTOTarget(target_minutes=240, measured_minutes=120, meets_target=True),
            summary="Test drill",
            details={"participants": ["team-a"]},
        )

        data = record.to_dict()

        assert data["record_id"] == str(record.record_id)
        assert data["evidence_type"] == "dr_drill"
        assert data["outcome"] == "success"
        assert data["executed_by"] == "operator-123"
        assert data["duration_seconds"] == 3600
        assert data["rpo"]["target_minutes"] == 60
        assert data["rto"]["target_minutes"] == 240
        assert data["summary"] == "Test drill"
        assert data["details"]["participants"] == ["team-a"]


# -----------------------------------------------------------------------------
# Summary Serialization Tests
# -----------------------------------------------------------------------------


class TestSummarySerialization:
    """Tests for summary serialization."""

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        now = datetime.now(UTC)
        summary = DREvidenceSummary(
            period_start=now - timedelta(days=30),
            period_end=now,
            backup_count=10,
            restore_test_count=2,
            dr_drill_count=1,
            success_rate=90.0,
            last_successful_backup=now - timedelta(days=1),
            last_restore_test=now - timedelta(days=7),
            last_dr_drill=now - timedelta(days=30),
            rpo_compliance=True,
            rto_compliance=True,
        )

        data = summary.to_dict()

        assert data["backup_count"] == 10
        assert data["restore_test_count"] == 2
        assert data["dr_drill_count"] == 1
        assert data["success_rate"] == 90.0
        assert data["rpo_compliance"] is True
        assert data["rto_compliance"] is True
