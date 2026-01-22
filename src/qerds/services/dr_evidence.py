"""DR (Disaster Recovery) evidence service.

Covers: REQ-D09 (Business continuity and DR), REQ-H08 (Business continuity evidence)

This module provides functionality to store and retrieve evidence of backup/restore
operations and DR exercises. Per the specs:

- The platform MUST enable automated backups for all durable state
- The platform MUST enable restore testing with verifiable results and logs
- The platform MUST enable DR exercises with exported evidence (timelines, RTO/RPO measurements)

Evidence types supported:
- Backup execution records (scheduled/manual backups with outcomes)
- Restore test results (validation of backup integrity)
- DR drill results (full DR exercise documentation)
- RPO/RTO measurements from actual tests

Note: The actual backup/restore operations are operator-managed infrastructure tasks.
This service stores the evidence artifacts for audit purposes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.services.storage import ObjectStoreClient

logger = logging.getLogger(__name__)


class DREvidenceType(Enum):
    """Types of DR/backup evidence artifacts.

    Values:
        BACKUP_EXECUTION: Record of a backup operation execution.
        RESTORE_TEST: Record of a restore validation test.
        DR_DRILL: Record of a full DR exercise/drill.
        RTO_MEASUREMENT: RTO (Recovery Time Objective) measurement.
        RPO_MEASUREMENT: RPO (Recovery Point Objective) measurement.
    """

    BACKUP_EXECUTION = "backup_execution"
    RESTORE_TEST = "restore_test"
    DR_DRILL = "dr_drill"
    RTO_MEASUREMENT = "rto_measurement"
    RPO_MEASUREMENT = "rpo_measurement"


class DREvidenceOutcome(Enum):
    """Outcome status for DR/backup operations.

    Values:
        SUCCESS: Operation completed successfully.
        PARTIAL: Operation completed with some issues.
        FAILURE: Operation failed.
        IN_PROGRESS: Operation is still running.
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    IN_PROGRESS = "in_progress"


@dataclass(frozen=True, slots=True)
class BackupScope:
    """Defines what is included in a backup.

    Attributes:
        postgresql: Whether PostgreSQL database is included.
        object_store: Whether object store (MinIO/S3) is included.
        audit_logs: Whether audit logs are included.
        config: Whether configuration is included.
    """

    postgresql: bool = True
    object_store: bool = True
    audit_logs: bool = True
    config: bool = True

    def to_dict(self) -> dict[str, bool]:
        """Convert to dictionary for serialization."""
        return {
            "postgresql": self.postgresql,
            "object_store": self.object_store,
            "audit_logs": self.audit_logs,
            "config": self.config,
        }

    @classmethod
    def from_dict(cls, data: dict[str, bool]) -> BackupScope:
        """Create from dictionary."""
        return cls(
            postgresql=data.get("postgresql", True),
            object_store=data.get("object_store", True),
            audit_logs=data.get("audit_logs", True),
            config=data.get("config", True),
        )


@dataclass(frozen=True, slots=True)
class RPOTarget:
    """RPO (Recovery Point Objective) target and measurement.

    Attributes:
        target_minutes: Target RPO in minutes.
        measured_minutes: Actual measured RPO (data loss) in minutes.
        meets_target: Whether the measured RPO meets the target.
    """

    target_minutes: int
    measured_minutes: float | None = None
    meets_target: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target_minutes": self.target_minutes,
            "measured_minutes": self.measured_minutes,
            "meets_target": self.meets_target,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RPOTarget:
        """Create from dictionary."""
        return cls(
            target_minutes=data["target_minutes"],
            measured_minutes=data.get("measured_minutes"),
            meets_target=data.get("meets_target"),
        )


@dataclass(frozen=True, slots=True)
class RTOTarget:
    """RTO (Recovery Time Objective) target and measurement.

    Attributes:
        target_minutes: Target RTO in minutes.
        measured_minutes: Actual measured RTO (recovery time) in minutes.
        meets_target: Whether the measured RTO meets the target.
    """

    target_minutes: int
    measured_minutes: float | None = None
    meets_target: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target_minutes": self.target_minutes,
            "measured_minutes": self.measured_minutes,
            "meets_target": self.meets_target,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RTOTarget:
        """Create from dictionary."""
        return cls(
            target_minutes=data["target_minutes"],
            measured_minutes=data.get("measured_minutes"),
            meets_target=data.get("meets_target"),
        )


@dataclass(frozen=True, slots=True)
class DREvidenceRecord:
    """A single DR/backup evidence record.

    Attributes:
        record_id: Unique identifier for this record.
        evidence_type: Type of evidence (backup, restore, drill, etc.).
        outcome: Outcome status of the operation.
        executed_at: When the operation was executed.
        executed_by: Who executed the operation (operator ID or system).
        duration_seconds: How long the operation took.
        backup_scope: What was included in the backup (for backup/restore types).
        rpo: RPO target and measurement (for DR drills).
        rto: RTO target and measurement (for DR drills).
        summary: Human-readable summary of the operation.
        details: Detailed structured data about the operation.
        artifact_refs: References to stored artifacts (logs, reports).
        record_hash: SHA-256 hash of the record for integrity.
        created_at: When this record was created.
    """

    record_id: uuid.UUID
    evidence_type: DREvidenceType
    outcome: DREvidenceOutcome
    executed_at: datetime
    executed_by: str
    duration_seconds: int | None
    backup_scope: BackupScope | None
    rpo: RPOTarget | None
    rto: RTOTarget | None
    summary: str
    details: dict[str, Any]
    artifact_refs: list[str]
    record_hash: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "record_id": str(self.record_id),
            "evidence_type": self.evidence_type.value,
            "outcome": self.outcome.value,
            "executed_at": self.executed_at.isoformat(),
            "executed_by": self.executed_by,
            "duration_seconds": self.duration_seconds,
            "backup_scope": self.backup_scope.to_dict() if self.backup_scope else None,
            "rpo": self.rpo.to_dict() if self.rpo else None,
            "rto": self.rto.to_dict() if self.rto else None,
            "summary": self.summary,
            "details": self.details,
            "artifact_refs": self.artifact_refs,
            "record_hash": self.record_hash,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class DREvidenceSummary:
    """Summary of DR evidence for a time period.

    Attributes:
        period_start: Start of the summary period.
        period_end: End of the summary period.
        backup_count: Number of backup executions.
        restore_test_count: Number of restore tests.
        dr_drill_count: Number of DR drills.
        success_rate: Percentage of successful operations.
        last_successful_backup: When the last successful backup occurred.
        last_restore_test: When the last restore test occurred.
        last_dr_drill: When the last DR drill occurred.
        rpo_compliance: Whether RPO targets are being met.
        rto_compliance: Whether RTO targets are being met.
    """

    period_start: datetime
    period_end: datetime
    backup_count: int
    restore_test_count: int
    dr_drill_count: int
    success_rate: float
    last_successful_backup: datetime | None
    last_restore_test: datetime | None
    last_dr_drill: datetime | None
    rpo_compliance: bool | None
    rto_compliance: bool | None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "backup_count": self.backup_count,
            "restore_test_count": self.restore_test_count,
            "dr_drill_count": self.dr_drill_count,
            "success_rate": self.success_rate,
            "last_successful_backup": (
                self.last_successful_backup.isoformat() if self.last_successful_backup else None
            ),
            "last_restore_test": (
                self.last_restore_test.isoformat() if self.last_restore_test else None
            ),
            "last_dr_drill": self.last_dr_drill.isoformat() if self.last_dr_drill else None,
            "rpo_compliance": self.rpo_compliance,
            "rto_compliance": self.rto_compliance,
        }


@dataclass
class DREvidenceConfig:
    """Configuration for DR evidence service.

    Attributes:
        evidence_bucket: S3 bucket for storing DR evidence artifacts.
        storage_prefix: Key prefix for evidence objects.
        default_rpo_minutes: Default RPO target in minutes.
        default_rto_minutes: Default RTO target in minutes.
    """

    evidence_bucket: str = "qerds-dr-evidence"
    storage_prefix: str = "dr-evidence/"
    default_rpo_minutes: int = 60  # 1 hour RPO target
    default_rto_minutes: int = 240  # 4 hour RTO target


class DREvidenceError(Exception):
    """Base exception for DR evidence operations."""

    pass


class DREvidenceStorageError(DREvidenceError):
    """Raised when evidence storage fails."""

    pass


class DREvidenceNotFoundError(DREvidenceError):
    """Raised when evidence record is not found."""

    pass


class DREvidenceService:
    """Service for storing and retrieving DR/backup evidence.

    This service stores evidence artifacts from backup/restore operations and
    DR exercises. The actual backup/restore operations are performed by
    operators using infrastructure tools; this service captures the evidence
    for audit purposes.

    Example:
        service = DREvidenceService(db_session, object_store)

        # Record a backup execution
        record = await service.record_backup_execution(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            backup_scope=BackupScope(),
            duration_seconds=120,
            summary="Scheduled daily backup completed",
            details={"backup_id": "backup-20240115-001"},
        )

        # Record a DR drill
        drill_record = await service.record_dr_drill(
            executed_by="operator-123",
            outcome=DREvidenceOutcome.SUCCESS,
            duration_seconds=14400,
            rpo=RPOTarget(target_minutes=60, measured_minutes=45, meets_target=True),
            rto=RTOTarget(target_minutes=240, measured_minutes=180, meets_target=True),
            summary="Q1 2024 DR drill completed successfully",
            details={"drill_id": "dr-drill-2024q1"},
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        object_store: ObjectStoreClient | None = None,
        config: DREvidenceConfig | None = None,
    ) -> None:
        """Initialize the DR evidence service.

        Args:
            session: Database session for storing evidence records.
            object_store: Object store client for storing artifacts.
            config: Optional configuration (uses defaults if None).
        """
        self._session = session
        self._object_store = object_store
        self._config = config or DREvidenceConfig()
        # In-memory storage for now; would be database-backed in production
        self._records: dict[uuid.UUID, DREvidenceRecord] = {}

    async def record_backup_execution(
        self,
        *,
        executed_by: str,
        outcome: DREvidenceOutcome,
        backup_scope: BackupScope | None = None,
        duration_seconds: int | None = None,
        summary: str,
        details: dict[str, Any] | None = None,
        artifact_data: bytes | None = None,
        artifact_filename: str | None = None,
        executed_at: datetime | None = None,
    ) -> DREvidenceRecord:
        """Record a backup execution event.

        Args:
            executed_by: ID of the operator or system that executed the backup.
            outcome: Outcome of the backup operation.
            backup_scope: What was included in the backup.
            duration_seconds: How long the backup took.
            summary: Human-readable summary.
            details: Detailed structured data.
            artifact_data: Optional artifact file content (e.g., backup log).
            artifact_filename: Filename for the artifact.
            executed_at: When the backup was executed (defaults to now).

        Returns:
            The created evidence record.
        """
        return await self._create_record(
            evidence_type=DREvidenceType.BACKUP_EXECUTION,
            outcome=outcome,
            executed_by=executed_by,
            backup_scope=backup_scope or BackupScope(),
            duration_seconds=duration_seconds,
            summary=summary,
            details=details or {},
            artifact_data=artifact_data,
            artifact_filename=artifact_filename,
            executed_at=executed_at,
        )

    async def record_restore_test(
        self,
        *,
        executed_by: str,
        outcome: DREvidenceOutcome,
        backup_scope: BackupScope | None = None,
        duration_seconds: int | None = None,
        summary: str,
        details: dict[str, Any] | None = None,
        artifact_data: bytes | None = None,
        artifact_filename: str | None = None,
        executed_at: datetime | None = None,
    ) -> DREvidenceRecord:
        """Record a restore test execution.

        Args:
            executed_by: ID of the operator that executed the test.
            outcome: Outcome of the restore test.
            backup_scope: What was restored.
            duration_seconds: How long the restore took.
            summary: Human-readable summary.
            details: Detailed structured data.
            artifact_data: Optional artifact file content (e.g., test log).
            artifact_filename: Filename for the artifact.
            executed_at: When the test was executed (defaults to now).

        Returns:
            The created evidence record.
        """
        return await self._create_record(
            evidence_type=DREvidenceType.RESTORE_TEST,
            outcome=outcome,
            executed_by=executed_by,
            backup_scope=backup_scope or BackupScope(),
            duration_seconds=duration_seconds,
            summary=summary,
            details=details or {},
            artifact_data=artifact_data,
            artifact_filename=artifact_filename,
            executed_at=executed_at,
        )

    async def record_dr_drill(
        self,
        *,
        executed_by: str,
        outcome: DREvidenceOutcome,
        duration_seconds: int | None = None,
        rpo: RPOTarget | None = None,
        rto: RTOTarget | None = None,
        summary: str,
        details: dict[str, Any] | None = None,
        artifact_data: bytes | None = None,
        artifact_filename: str | None = None,
        executed_at: datetime | None = None,
    ) -> DREvidenceRecord:
        """Record a DR drill/exercise.

        Args:
            executed_by: ID of the operator that conducted the drill.
            outcome: Outcome of the DR drill.
            duration_seconds: Total duration of the drill.
            rpo: RPO target and measured value.
            rto: RTO target and measured value.
            summary: Human-readable summary.
            details: Detailed structured data (runbook steps, participants, etc.).
            artifact_data: Optional artifact file content (e.g., drill report).
            artifact_filename: Filename for the artifact.
            executed_at: When the drill was executed (defaults to now).

        Returns:
            The created evidence record.
        """
        # Use default targets if not provided
        if rpo is None:
            rpo = RPOTarget(target_minutes=self._config.default_rpo_minutes)
        if rto is None:
            rto = RTOTarget(target_minutes=self._config.default_rto_minutes)

        return await self._create_record(
            evidence_type=DREvidenceType.DR_DRILL,
            outcome=outcome,
            executed_by=executed_by,
            duration_seconds=duration_seconds,
            rpo=rpo,
            rto=rto,
            summary=summary,
            details=details or {},
            artifact_data=artifact_data,
            artifact_filename=artifact_filename,
            executed_at=executed_at,
        )

    async def _create_record(
        self,
        *,
        evidence_type: DREvidenceType,
        outcome: DREvidenceOutcome,
        executed_by: str,
        backup_scope: BackupScope | None = None,
        duration_seconds: int | None = None,
        rpo: RPOTarget | None = None,
        rto: RTOTarget | None = None,
        summary: str,
        details: dict[str, Any],
        artifact_data: bytes | None = None,
        artifact_filename: str | None = None,
        executed_at: datetime | None = None,
    ) -> DREvidenceRecord:
        """Create and store a DR evidence record.

        Internal method that handles record creation and artifact storage.
        """
        record_id = uuid.uuid4()
        created_at = datetime.now(UTC)
        executed_at = executed_at or created_at

        # Store artifact if provided
        artifact_refs: list[str] = []
        if artifact_data and self._object_store:
            artifact_ref = await self._store_artifact(
                record_id=record_id,
                data=artifact_data,
                filename=artifact_filename or f"{evidence_type.value}_log.txt",
            )
            artifact_refs.append(artifact_ref)

        # Build record data for hashing
        record_data = {
            "record_id": str(record_id),
            "evidence_type": evidence_type.value,
            "outcome": outcome.value,
            "executed_at": executed_at.isoformat(),
            "executed_by": executed_by,
            "duration_seconds": duration_seconds,
            "backup_scope": backup_scope.to_dict() if backup_scope else None,
            "rpo": rpo.to_dict() if rpo else None,
            "rto": rto.to_dict() if rto else None,
            "summary": summary,
            "details": details,
            "artifact_refs": artifact_refs,
        }

        # Compute record hash for integrity
        record_hash = hashlib.sha256(
            json.dumps(record_data, sort_keys=True, default=str).encode()
        ).hexdigest()

        record = DREvidenceRecord(
            record_id=record_id,
            evidence_type=evidence_type,
            outcome=outcome,
            executed_at=executed_at,
            executed_by=executed_by,
            duration_seconds=duration_seconds,
            backup_scope=backup_scope,
            rpo=rpo,
            rto=rto,
            summary=summary,
            details=details,
            artifact_refs=artifact_refs,
            record_hash=record_hash,
            created_at=created_at,
        )

        # Store in memory (would be database in production)
        self._records[record_id] = record

        logger.info(
            "DR evidence recorded: record_id=%s, type=%s, outcome=%s",
            record_id,
            evidence_type.value,
            outcome.value,
        )

        return record

    async def _store_artifact(
        self,
        *,
        record_id: uuid.UUID,
        data: bytes,
        filename: str,
    ) -> str:
        """Store an artifact file to object storage.

        Args:
            record_id: Associated evidence record ID.
            data: File content.
            filename: Original filename.

        Returns:
            Storage reference (S3 URI).

        Raises:
            DREvidenceStorageError: If storage fails.
        """
        if not self._object_store:
            msg = "Object store not configured"
            raise DREvidenceStorageError(msg)

        storage_key = f"{self._config.storage_prefix}{record_id}/{filename}"

        try:
            self._object_store.ensure_bucket(self._config.evidence_bucket)
            self._object_store.upload(
                bucket=self._config.evidence_bucket,
                key=storage_key,
                data=data,
                content_type="application/octet-stream",
                metadata={
                    "record-id": str(record_id),
                    "filename": filename,
                },
            )

            return f"s3://{self._config.evidence_bucket}/{storage_key}"

        except Exception as e:
            msg = f"Failed to store artifact for record {record_id}: {e}"
            raise DREvidenceStorageError(msg) from e

    async def get_record(self, record_id: uuid.UUID) -> DREvidenceRecord:
        """Get a DR evidence record by ID.

        Args:
            record_id: The record ID.

        Returns:
            The evidence record.

        Raises:
            DREvidenceNotFoundError: If record not found.
        """
        if record_id not in self._records:
            msg = f"DR evidence record {record_id} not found"
            raise DREvidenceNotFoundError(msg)
        return self._records[record_id]

    async def list_records(
        self,
        *,
        evidence_type: DREvidenceType | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
    ) -> list[DREvidenceRecord]:
        """List DR evidence records with optional filtering.

        Args:
            evidence_type: Filter by evidence type.
            start_date: Filter by executed_at >= start_date.
            end_date: Filter by executed_at <= end_date.
            limit: Maximum number of records to return.

        Returns:
            List of matching evidence records, sorted by executed_at descending.
        """
        records = list(self._records.values())

        # Apply filters
        if evidence_type:
            records = [r for r in records if r.evidence_type == evidence_type]
        if start_date:
            records = [r for r in records if r.executed_at >= start_date]
        if end_date:
            records = [r for r in records if r.executed_at <= end_date]

        # Sort by executed_at descending
        records.sort(key=lambda r: r.executed_at, reverse=True)

        return records[:limit]

    async def get_summary(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> DREvidenceSummary:
        """Get a summary of DR evidence for a time period.

        Args:
            start_date: Start of the period.
            end_date: End of the period.

        Returns:
            Summary statistics for the period.
        """
        records = await self.list_records(
            start_date=start_date,
            end_date=end_date,
            limit=10000,  # Get all records in range
        )

        # Count by type
        backup_count = sum(1 for r in records if r.evidence_type == DREvidenceType.BACKUP_EXECUTION)
        restore_test_count = sum(
            1 for r in records if r.evidence_type == DREvidenceType.RESTORE_TEST
        )
        dr_drill_count = sum(1 for r in records if r.evidence_type == DREvidenceType.DR_DRILL)

        # Calculate success rate
        total = len(records)
        successful = sum(1 for r in records if r.outcome == DREvidenceOutcome.SUCCESS)
        success_rate = (successful / total * 100) if total > 0 else 0.0

        # Find last successful operations
        successful_backups = [
            r
            for r in records
            if r.evidence_type == DREvidenceType.BACKUP_EXECUTION
            and r.outcome == DREvidenceOutcome.SUCCESS
        ]
        last_successful_backup = (
            max(successful_backups, key=lambda r: r.executed_at).executed_at
            if successful_backups
            else None
        )

        restore_tests = [r for r in records if r.evidence_type == DREvidenceType.RESTORE_TEST]
        last_restore_test = (
            max(restore_tests, key=lambda r: r.executed_at).executed_at if restore_tests else None
        )

        dr_drills = [r for r in records if r.evidence_type == DREvidenceType.DR_DRILL]
        last_dr_drill = (
            max(dr_drills, key=lambda r: r.executed_at).executed_at if dr_drills else None
        )

        # Check RPO/RTO compliance from DR drills
        rpo_compliance = None
        rto_compliance = None
        if dr_drills:
            rpo_results = [
                d.rpo.meets_target for d in dr_drills if d.rpo and d.rpo.meets_target is not None
            ]
            rto_results = [
                d.rto.meets_target for d in dr_drills if d.rto and d.rto.meets_target is not None
            ]
            rpo_compliance = all(rpo_results) if rpo_results else None
            rto_compliance = all(rto_results) if rto_results else None

        return DREvidenceSummary(
            period_start=start_date,
            period_end=end_date,
            backup_count=backup_count,
            restore_test_count=restore_test_count,
            dr_drill_count=dr_drill_count,
            success_rate=success_rate,
            last_successful_backup=last_successful_backup,
            last_restore_test=last_restore_test,
            last_dr_drill=last_dr_drill,
            rpo_compliance=rpo_compliance,
            rto_compliance=rto_compliance,
        )

    async def get_records_for_audit_pack(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> list[dict[str, Any]]:
        """Get DR evidence records formatted for inclusion in audit packs.

        This method returns records in a format suitable for the audit pack
        export functionality (REQ-H01, REQ-H08).

        Args:
            start_date: Start of the date range.
            end_date: End of the date range.

        Returns:
            List of record dictionaries formatted for audit pack.
        """
        records = await self.list_records(
            start_date=start_date,
            end_date=end_date,
            limit=10000,
        )

        return [r.to_dict() for r in records]


async def create_dr_evidence_service(
    session: AsyncSession,
    object_store: ObjectStoreClient | None = None,
    *,
    evidence_bucket: str = "qerds-dr-evidence",
    storage_prefix: str = "dr-evidence/",
    default_rpo_minutes: int = 60,
    default_rto_minutes: int = 240,
) -> DREvidenceService:
    """Factory function to create a DREvidenceService.

    Args:
        session: Database session.
        object_store: Object store client for artifacts.
        evidence_bucket: S3 bucket for evidence.
        storage_prefix: Key prefix for evidence objects.
        default_rpo_minutes: Default RPO target.
        default_rto_minutes: Default RTO target.

    Returns:
        Configured DREvidenceService instance.
    """
    config = DREvidenceConfig(
        evidence_bucket=evidence_bucket,
        storage_prefix=storage_prefix,
        default_rpo_minutes=default_rpo_minutes,
        default_rto_minutes=default_rto_minutes,
    )
    return DREvidenceService(session, object_store, config)
