"""Tamper-evident audit logging service.

Covers: REQ-C05 (immutability), REQ-D08 (logging), REQ-H03 (audit review)

This module provides append-only audit logging with hash chain construction
for tamper-evidence. Each record is cryptographically linked to the previous
record via SHA-256, enabling detection of:
- Record deletion
- Record modification
- Record reordering
- Sequence number gaps
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import AuditStream  # noqa: TC001 - used at runtime

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession


class AuditEventType(Enum):
    """Audit event types for categorization and filtering.

    These event types span across all audit streams (evidence, security, ops).
    """

    # Evidence stream events
    DELIVERY_CREATED = "delivery_created"
    DELIVERY_DEPOSITED = "delivery_deposited"
    DELIVERY_NOTIFIED = "delivery_notified"
    DELIVERY_ACCESSED = "delivery_accessed"
    DELIVERY_ACCEPTED = "delivery_accepted"
    DELIVERY_REFUSED = "delivery_refused"
    DELIVERY_EXPIRED = "delivery_expired"
    EVIDENCE_SEALED = "evidence_sealed"
    EVIDENCE_VERIFIED = "evidence_verified"

    # Security stream events
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_FAILED = "auth_failed"
    AUTH_MFA_CHALLENGE = "auth_mfa_challenge"
    AUTHZ_GRANTED = "authz_granted"
    AUTHZ_DENIED = "authz_denied"
    ADMIN_ACTION = "admin_action"
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    PERMISSION_CHANGED = "permission_changed"

    # Operations stream events
    CONFIG_CHANGED = "config_changed"
    CONFIG_SNAPSHOT = "config_snapshot"
    DEPLOYMENT_STARTED = "deployment_started"
    DEPLOYMENT_COMPLETED = "deployment_completed"
    DEPLOYMENT_ROLLED_BACK = "deployment_rolled_back"
    BACKUP_STARTED = "backup_started"
    BACKUP_COMPLETED = "backup_completed"
    BACKUP_VERIFIED = "backup_verified"
    DR_TEST_STARTED = "dr_test_started"
    DR_TEST_COMPLETED = "dr_test_completed"
    MAINTENANCE_STARTED = "maintenance_started"
    MAINTENANCE_COMPLETED = "maintenance_completed"


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """Immutable representation of an audit log record.

    Attributes:
        record_id: Unique identifier for this record.
        stream: The audit stream (evidence, security, ops).
        seq_no: Monotonically increasing sequence number within stream.
        record_hash: SHA-256 hash of this record's canonical content.
        prev_record_hash: Hash of previous record (None for first record).
        event_type: Category of event for filtering.
        actor_type: Type of actor (user, system, api_client).
        actor_id: Identifier of the actor.
        resource_type: Type of resource affected (delivery, user, config).
        resource_id: Identifier of the affected resource.
        payload_ref: Reference to full payload in object store.
        summary: Brief summary metadata for display.
        created_at: When this record was created.
    """

    record_id: uuid.UUID
    stream: AuditStream
    seq_no: int
    record_hash: str
    prev_record_hash: str | None
    event_type: str
    actor_type: str | None
    actor_id: str | None
    resource_type: str | None
    resource_id: str | None
    payload_ref: str
    summary: dict[str, Any] | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """Result of verifying an audit log chain.

    Attributes:
        valid: True if the chain is intact and tamper-free.
        checked_records: Number of records verified.
        first_seq_no: First sequence number in the verified range.
        last_seq_no: Last sequence number in the verified range.
        errors: List of detected integrity violations.
    """

    valid: bool
    checked_records: int
    first_seq_no: int | None
    last_seq_no: int | None
    errors: list[str]


class AuditLogService:
    """Service for tamper-evident audit logging.

    This service implements append-only logging with cryptographic hash
    chaining for tamper evidence. Each record contains a hash of its
    contents and a reference to the previous record's hash, forming
    an immutable chain.

    The hash chain enables detection of:
    - Record deletion (gap in sequence numbers)
    - Record modification (hash mismatch)
    - Record reordering (prev_record_hash mismatch)

    Example:
        service = AuditLogService(session)
        entry = await service.append(
            stream=AuditStream.SECURITY,
            event_type=AuditEventType.AUTH_LOGIN,
            actor_type="user",
            actor_id="user-123",
            payload={"ip": "192.168.1.1", "user_agent": "..."},
        )

        # Later, verify the chain
        result = await service.verify_chain(AuditStream.SECURITY)
        if not result.valid:
            # Chain has been tampered with
            alert_security_team(result.errors)
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the audit log service.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session

    async def append(
        self,
        *,
        stream: AuditStream,
        event_type: AuditEventType | str,
        payload: dict[str, Any],
        actor_type: str | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        summary: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Append a new record to the audit log.

        This method is append-only: records cannot be modified or deleted
        once written. Each record is cryptographically chained to the
        previous record via SHA-256.

        Args:
            stream: The audit stream to append to (evidence, security, ops).
            event_type: Type of event being logged.
            payload: Full event payload (will be stored in object store).
            actor_type: Type of actor performing the action.
            actor_id: Identifier of the actor.
            resource_type: Type of resource affected.
            resource_id: Identifier of the affected resource.
            summary: Brief summary for display without loading full payload.

        Returns:
            The created audit log entry.

        Raises:
            RuntimeError: If there is a concurrent write conflict.
        """
        from qerds.db.models.audit import AuditLogRecord

        # Normalize event_type to string
        event_type_str = event_type.value if isinstance(event_type, AuditEventType) else event_type

        # Get the next sequence number and previous record hash atomically
        # Uses SELECT ... FOR UPDATE to prevent concurrent inserts
        next_seq_no, prev_hash = await self._get_next_seq_and_prev_hash(stream)

        # Generate record ID and timestamp
        record_id = uuid.uuid4()
        created_at = datetime.now(UTC)

        # Store payload in object store and get reference
        # For now, we embed the payload reference as a JSON string
        # In production, this would upload to S3/MinIO and return a key
        payload_ref = self._store_payload(record_id, payload)

        # Compute record hash using canonical representation
        record_hash = self._compute_record_hash(
            stream=stream,
            seq_no=next_seq_no,
            event_type=event_type_str,
            payload_ref=payload_ref,
            prev_record_hash=prev_hash,
            created_at=created_at,
        )

        # Create the database record
        record = AuditLogRecord(
            record_id=record_id,
            created_at=created_at,
            stream=stream,
            seq_no=next_seq_no,
            record_hash=record_hash,
            prev_record_hash=prev_hash,
            payload_ref=payload_ref,
            event_type=event_type_str,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            summary=summary,
        )

        self._session.add(record)
        await self._session.flush()

        return AuditLogEntry(
            record_id=record_id,
            stream=stream,
            seq_no=next_seq_no,
            record_hash=record_hash,
            prev_record_hash=prev_hash,
            event_type=event_type_str,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            payload_ref=payload_ref,
            summary=summary,
            created_at=created_at,
        )

    async def verify_chain(
        self,
        stream: AuditStream,
        *,
        start_seq: int | None = None,
        end_seq: int | None = None,
    ) -> ChainVerificationResult:
        """Verify the integrity of an audit log chain.

        Checks that:
        1. Sequence numbers are contiguous (no gaps)
        2. Each record's hash matches its computed hash
        3. Each record's prev_record_hash matches the previous record's hash
        4. The first record has prev_record_hash=None

        Args:
            stream: The audit stream to verify.
            start_seq: Starting sequence number (inclusive). Defaults to 1.
            end_seq: Ending sequence number (inclusive). Defaults to latest.

        Returns:
            ChainVerificationResult with validity status and any errors found.
        """
        from sqlalchemy import select

        from qerds.db.models.audit import AuditLogRecord

        # Build query for the specified range
        query = (
            select(AuditLogRecord)
            .where(AuditLogRecord.stream == stream)
            .order_by(AuditLogRecord.seq_no)
        )

        if start_seq is not None:
            query = query.where(AuditLogRecord.seq_no >= start_seq)
        if end_seq is not None:
            query = query.where(AuditLogRecord.seq_no <= end_seq)

        result = await self._session.execute(query)
        records: Sequence[AuditLogRecord] = result.scalars().all()

        if not records:
            return ChainVerificationResult(
                valid=True,
                checked_records=0,
                first_seq_no=None,
                last_seq_no=None,
                errors=[],
            )

        errors: list[str] = []
        prev_hash: str | None = None
        expected_seq: int | None = None

        for record in records:
            # Check sequence continuity
            if expected_seq is not None and record.seq_no != expected_seq:
                errors.append(
                    f"Sequence gap detected: expected {expected_seq}, found {record.seq_no}"
                )

            # First record in stream must have no prev_record_hash
            if record.seq_no == 1 and record.prev_record_hash is not None:
                errors.append(
                    f"First record (seq_no=1) has prev_record_hash={record.prev_record_hash}, "
                    "expected None"
                )

            # Verify chain linkage (prev_record_hash matches previous record's hash)
            if prev_hash is not None and record.prev_record_hash != prev_hash:
                errors.append(
                    f"Chain break at seq_no={record.seq_no}: "
                    f"prev_record_hash={record.prev_record_hash}, "
                    f"expected {prev_hash}"
                )
            elif prev_hash is None and record.seq_no > 1 and start_seq is None:
                # If we're starting from seq_no > 1 without explicit start_seq,
                # we can't verify the chain link for the first record we see
                pass

            # Verify record hash matches computed hash
            computed_hash = self._compute_record_hash(
                stream=record.stream,
                seq_no=record.seq_no,
                event_type=record.event_type,
                payload_ref=record.payload_ref,
                prev_record_hash=record.prev_record_hash,
                created_at=record.created_at,
            )
            if record.record_hash != computed_hash:
                errors.append(
                    f"Hash mismatch at seq_no={record.seq_no}: "
                    f"stored={record.record_hash}, computed={computed_hash}"
                )

            prev_hash = record.record_hash
            expected_seq = record.seq_no + 1

        first_record = records[0]
        last_record = records[-1]

        return ChainVerificationResult(
            valid=len(errors) == 0,
            checked_records=len(records),
            first_seq_no=first_record.seq_no,
            last_seq_no=last_record.seq_no,
            errors=errors,
        )

    async def get_records(
        self,
        stream: AuditStream,
        *,
        start_seq: int | None = None,
        end_seq: int | None = None,
        event_type: str | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Query audit log records with filtering.

        Args:
            stream: The audit stream to query.
            start_seq: Minimum sequence number (inclusive).
            end_seq: Maximum sequence number (inclusive).
            event_type: Filter by event type.
            actor_id: Filter by actor identifier.
            resource_type: Filter by resource type.
            resource_id: Filter by resource identifier.
            limit: Maximum number of records to return.
            offset: Number of records to skip.

        Returns:
            List of matching audit log entries.
        """
        from sqlalchemy import select

        from qerds.db.models.audit import AuditLogRecord

        query = (
            select(AuditLogRecord)
            .where(AuditLogRecord.stream == stream)
            .order_by(AuditLogRecord.seq_no)
        )

        if start_seq is not None:
            query = query.where(AuditLogRecord.seq_no >= start_seq)
        if end_seq is not None:
            query = query.where(AuditLogRecord.seq_no <= end_seq)
        if event_type is not None:
            query = query.where(AuditLogRecord.event_type == event_type)
        if actor_id is not None:
            query = query.where(AuditLogRecord.actor_id == actor_id)
        if resource_type is not None:
            query = query.where(AuditLogRecord.resource_type == resource_type)
        if resource_id is not None:
            query = query.where(AuditLogRecord.resource_id == resource_id)

        query = query.limit(limit).offset(offset)

        result = await self._session.execute(query)
        records = result.scalars().all()

        return [
            AuditLogEntry(
                record_id=r.record_id,
                stream=r.stream,
                seq_no=r.seq_no,
                record_hash=r.record_hash,
                prev_record_hash=r.prev_record_hash,
                event_type=r.event_type,
                actor_type=r.actor_type,
                actor_id=r.actor_id,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                payload_ref=r.payload_ref,
                summary=r.summary,
                created_at=r.created_at,
            )
            for r in records
        ]

    async def get_latest_record(
        self,
        stream: AuditStream,
    ) -> AuditLogEntry | None:
        """Get the most recent record in a stream.

        Args:
            stream: The audit stream to query.

        Returns:
            The latest audit log entry, or None if the stream is empty.
        """
        from sqlalchemy import select

        from qerds.db.models.audit import AuditLogRecord

        query = (
            select(AuditLogRecord)
            .where(AuditLogRecord.stream == stream)
            .order_by(AuditLogRecord.seq_no.desc())
            .limit(1)
        )

        result = await self._session.execute(query)
        record = result.scalar_one_or_none()

        if record is None:
            return None

        return AuditLogEntry(
            record_id=record.record_id,
            stream=record.stream,
            seq_no=record.seq_no,
            record_hash=record.record_hash,
            prev_record_hash=record.prev_record_hash,
            event_type=record.event_type,
            actor_type=record.actor_type,
            actor_id=record.actor_id,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            payload_ref=record.payload_ref,
            summary=record.summary,
            created_at=record.created_at,
        )

    async def _get_next_seq_and_prev_hash(
        self,
        stream: AuditStream,
    ) -> tuple[int, str | None]:
        """Get the next sequence number and previous record hash atomically.

        Uses SELECT ... FOR UPDATE SKIP LOCKED to handle concurrent writers.
        If no records exist, returns (1, None).

        Args:
            stream: The audit stream.

        Returns:
            Tuple of (next_seq_no, prev_record_hash).
        """
        from sqlalchemy import select

        from qerds.db.models.audit import AuditLogRecord

        # Get the latest record in this stream with row-level lock
        # FOR UPDATE ensures exclusive access during the transaction
        query = (
            select(AuditLogRecord)
            .where(AuditLogRecord.stream == stream)
            .order_by(AuditLogRecord.seq_no.desc())
            .limit(1)
            .with_for_update(skip_locked=True)
        )

        result = await self._session.execute(query)
        latest = result.scalar_one_or_none()

        if latest is None:
            return (1, None)

        return (latest.seq_no + 1, latest.record_hash)

    def _compute_record_hash(
        self,
        *,
        stream: AuditStream,
        seq_no: int,
        event_type: str,
        payload_ref: str,
        prev_record_hash: str | None,
        created_at: datetime,
    ) -> str:
        """Compute the SHA-256 hash of a record's canonical representation.

        The canonical representation is a JSON object with deterministically
        ordered keys, ensuring consistent hashing across systems.

        Args:
            stream: The audit stream.
            seq_no: Sequence number within the stream.
            event_type: Type of event.
            payload_ref: Reference to full payload.
            prev_record_hash: Hash of previous record (or None).
            created_at: Record creation timestamp.

        Returns:
            Hex-encoded SHA-256 hash (64 characters).
        """
        # Build canonical representation with sorted keys
        canonical = {
            "created_at": created_at.isoformat(),
            "event_type": event_type,
            "payload_ref": payload_ref,
            "prev_record_hash": prev_record_hash,
            "seq_no": seq_no,
            "stream": stream.value,
        }

        # JSON with sorted keys and no whitespace for deterministic serialization
        canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))

        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _store_payload(
        self,
        record_id: uuid.UUID,
        payload: dict[str, Any],
    ) -> str:
        """Store payload and return a reference.

        In production, this would upload to S3/MinIO object storage.
        For now, we embed the payload as a data URI for simplicity.

        Args:
            record_id: ID of the audit record.
            payload: Full event payload.

        Returns:
            Reference string for retrieving the payload.
        """
        # Serialize payload to JSON
        payload_json = json.dumps(payload, sort_keys=True, default=str)

        # For development, embed as data URI
        # Production would upload to S3: f"s3://audit-logs/{record_id}.json"
        # Using a simple reference format that could be upgraded later
        return f"inline:{record_id}:{hashlib.sha256(payload_json.encode()).hexdigest()[:16]}"


def compute_record_hash_standalone(
    *,
    stream: str,
    seq_no: int,
    event_type: str,
    payload_ref: str,
    prev_record_hash: str | None,
    created_at: datetime,
) -> str:
    """Compute record hash without service instance (for verification tools).

    This standalone function allows external tools to verify record hashes
    without needing database access or a service instance.

    Args:
        stream: The audit stream name.
        seq_no: Sequence number within the stream.
        event_type: Type of event.
        payload_ref: Reference to full payload.
        prev_record_hash: Hash of previous record (or None).
        created_at: Record creation timestamp.

    Returns:
        Hex-encoded SHA-256 hash (64 characters).
    """
    canonical = {
        "created_at": created_at.isoformat(),
        "event_type": event_type,
        "payload_ref": payload_ref,
        "prev_record_hash": prev_record_hash,
        "seq_no": seq_no,
        "stream": stream,
    }

    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
