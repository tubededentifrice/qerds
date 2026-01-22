"""Tests for tamper-evident audit logging service.

Tests cover:
- Append-only logging behavior
- Hash chain construction and integrity
- Tampering detection (modification, deletion, reordering)
- Sequence number continuity
- Multi-stream isolation
"""

import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import (
    AuditEventType,
    AuditLogEntry,
    AuditLogService,
    ChainVerificationResult,
    compute_record_hash_standalone,
)


class TestAuditLogServiceAppend:
    """Tests for the append operation."""

    @pytest.mark.asyncio
    async def test_append_creates_record_with_hash(self):
        """Appending a record computes and stores a hash."""
        session = create_mock_session(existing_records=[])

        service = AuditLogService(session)
        entry = await service.append(
            stream=AuditStream.SECURITY,
            event_type=AuditEventType.AUTH_LOGIN,
            payload={"user": "test@example.com", "ip": "192.168.1.1"},
            actor_type="user",
            actor_id="user-123",
        )

        assert entry.record_hash is not None
        assert len(entry.record_hash) == 64  # SHA-256 hex = 64 chars
        assert entry.seq_no == 1
        assert entry.prev_record_hash is None  # First record has no predecessor

    @pytest.mark.asyncio
    async def test_append_chains_to_previous_record(self):
        """Appending links new record to previous via prev_record_hash."""
        # Create a mock previous record
        prev_record = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash="abc123def456" + "0" * 52,  # 64 chars
            prev_record_hash=None,
        )
        session = create_mock_session(existing_records=[prev_record])

        service = AuditLogService(session)
        entry = await service.append(
            stream=AuditStream.SECURITY,
            event_type=AuditEventType.AUTH_LOGOUT,
            payload={"user": "test@example.com"},
        )

        assert entry.seq_no == 2
        assert entry.prev_record_hash == prev_record.record_hash

    @pytest.mark.asyncio
    async def test_append_with_all_fields(self):
        """Appending with all optional fields populates the entry."""
        session = create_mock_session(existing_records=[])

        service = AuditLogService(session)
        summary = {"action": "login", "success": True}
        entry = await service.append(
            stream=AuditStream.SECURITY,
            event_type=AuditEventType.AUTH_LOGIN,
            payload={"full": "payload"},
            actor_type="user",
            actor_id="user-456",
            resource_type="session",
            resource_id="sess-789",
            summary=summary,
        )

        assert entry.actor_type == "user"
        assert entry.actor_id == "user-456"
        assert entry.resource_type == "session"
        assert entry.resource_id == "sess-789"
        assert entry.summary == summary

    @pytest.mark.asyncio
    async def test_append_accepts_string_event_type(self):
        """Appending accepts string event type in addition to enum."""
        session = create_mock_session(existing_records=[])

        service = AuditLogService(session)
        entry = await service.append(
            stream=AuditStream.OPS,
            event_type="custom_event_type",
            payload={"custom": "data"},
        )

        assert entry.event_type == "custom_event_type"

    @pytest.mark.asyncio
    async def test_append_isolates_streams(self):
        """Records in different streams have independent sequence numbers."""
        # Security stream has records, evidence stream is empty
        security_record = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=5,
            record_hash="security_hash" + "0" * 51,
        )
        session = create_mock_session(
            existing_records=[security_record],
            stream_filter=AuditStream.EVIDENCE,  # Query for evidence returns empty
        )

        service = AuditLogService(session)
        entry = await service.append(
            stream=AuditStream.EVIDENCE,
            event_type=AuditEventType.DELIVERY_CREATED,
            payload={"delivery_id": "del-123"},
        )

        # Evidence stream starts at seq_no=1 despite security having seq_no=5
        assert entry.seq_no == 1
        assert entry.prev_record_hash is None


class TestAuditLogServiceVerifyChain:
    """Tests for chain verification."""

    @pytest.mark.asyncio
    async def test_verify_empty_chain_is_valid(self):
        """Empty chain (no records) is considered valid."""
        session = create_mock_session(existing_records=[])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is True
        assert result.checked_records == 0
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_verify_single_record_chain(self):
        """Single record chain with correct hash is valid."""
        created_at = datetime.now(UTC)
        record_hash = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test:abc123",
            prev_record_hash=None,
            created_at=created_at,
        )

        record = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash=record_hash,
            prev_record_hash=None,
            event_type="auth_login",
            payload_ref="inline:test:abc123",
            created_at=created_at,
        )
        session = create_mock_session_for_verify([record])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is True
        assert result.checked_records == 1
        assert result.first_seq_no == 1
        assert result.last_seq_no == 1

    @pytest.mark.asyncio
    async def test_verify_detects_hash_modification(self):
        """Verification detects when a record's hash has been modified."""
        created_at = datetime.now(UTC)
        # Note: correct hash would be computed from the record data,
        # but we're testing that the service detects a tampered hash

        # Create record with wrong hash (simulating tampering)
        record = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash="tampered_hash" + "0" * 51,  # Wrong hash
            prev_record_hash=None,
            event_type="auth_login",
            payload_ref="inline:test:abc123",
            created_at=created_at,
        )
        session = create_mock_session_for_verify([record])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is False
        assert len(result.errors) == 1
        assert "Hash mismatch" in result.errors[0]

    @pytest.mark.asyncio
    async def test_verify_detects_chain_break(self):
        """Verification detects when prev_record_hash doesn't match."""
        created_at = datetime.now(UTC)

        # First record
        hash1 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test:111",
            prev_record_hash=None,
            created_at=created_at,
        )
        record1 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash=hash1,
            prev_record_hash=None,
            event_type="auth_login",
            payload_ref="inline:test:111",
            created_at=created_at,
        )

        # Second record with WRONG prev_record_hash (should be hash1)
        hash2 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=2,
            event_type="auth_logout",
            payload_ref="inline:test:222",
            prev_record_hash="wrong_prev_hash" + "0" * 50,
            created_at=created_at,
        )
        record2 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=2,
            record_hash=hash2,
            prev_record_hash="wrong_prev_hash" + "0" * 50,  # Wrong!
            event_type="auth_logout",
            payload_ref="inline:test:222",
            created_at=created_at,
        )

        session = create_mock_session_for_verify([record1, record2])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is False
        assert any("Chain break" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_verify_detects_sequence_gap(self):
        """Verification detects gaps in sequence numbers (deleted records)."""
        created_at = datetime.now(UTC)

        # Record 1
        hash1 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test:111",
            prev_record_hash=None,
            created_at=created_at,
        )
        record1 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash=hash1,
            prev_record_hash=None,
            event_type="auth_login",
            payload_ref="inline:test:111",
            created_at=created_at,
        )

        # Record 3 (seq_no=2 is missing - simulating deletion)
        hash3 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=3,
            event_type="auth_logout",
            payload_ref="inline:test:333",
            prev_record_hash="some_hash" + "0" * 55,
            created_at=created_at,
        )
        record3 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=3,  # Gap! Missing seq_no=2
            record_hash=hash3,
            prev_record_hash="some_hash" + "0" * 55,
            event_type="auth_logout",
            payload_ref="inline:test:333",
            created_at=created_at,
        )

        session = create_mock_session_for_verify([record1, record3])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is False
        assert any("Sequence gap" in e for e in result.errors)
        assert any("expected 2" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_verify_detects_wrong_first_record(self):
        """Verification fails if first record has non-null prev_record_hash."""
        created_at = datetime.now(UTC)

        # First record with non-null prev_record_hash (invalid)
        hash1 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test:111",
            prev_record_hash="should_be_null" + "0" * 50,
            created_at=created_at,
        )
        record1 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash=hash1,
            prev_record_hash="should_be_null" + "0" * 50,  # Should be None!
            event_type="auth_login",
            payload_ref="inline:test:111",
            created_at=created_at,
        )

        session = create_mock_session_for_verify([record1])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is False
        assert any("First record" in e and "expected None" in e for e in result.errors)

    @pytest.mark.asyncio
    async def test_verify_valid_multi_record_chain(self):
        """Valid chain with multiple records passes verification."""
        created_at = datetime.now(UTC)

        # Build a valid chain of 3 records
        hash1 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test:111",
            prev_record_hash=None,
            created_at=created_at,
        )
        record1 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash=hash1,
            prev_record_hash=None,
            event_type="auth_login",
            payload_ref="inline:test:111",
            created_at=created_at,
        )

        hash2 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=2,
            event_type="auth_mfa_challenge",
            payload_ref="inline:test:222",
            prev_record_hash=hash1,
            created_at=created_at,
        )
        record2 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=2,
            record_hash=hash2,
            prev_record_hash=hash1,
            event_type="auth_mfa_challenge",
            payload_ref="inline:test:222",
            created_at=created_at,
        )

        hash3 = compute_test_hash(
            stream=AuditStream.SECURITY,
            seq_no=3,
            event_type="auth_logout",
            payload_ref="inline:test:333",
            prev_record_hash=hash2,
            created_at=created_at,
        )
        record3 = create_mock_record(
            stream=AuditStream.SECURITY,
            seq_no=3,
            record_hash=hash3,
            prev_record_hash=hash2,
            event_type="auth_logout",
            payload_ref="inline:test:333",
            created_at=created_at,
        )

        session = create_mock_session_for_verify([record1, record2, record3])

        service = AuditLogService(session)
        result = await service.verify_chain(AuditStream.SECURITY)

        assert result.valid is True
        assert result.checked_records == 3
        assert result.first_seq_no == 1
        assert result.last_seq_no == 3
        assert result.errors == []


class TestHashComputation:
    """Tests for hash computation consistency."""

    def test_hash_is_deterministic(self):
        """Same inputs always produce the same hash."""
        created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

        hash1 = compute_record_hash_standalone(
            stream="security",
            seq_no=42,
            event_type="auth_login",
            payload_ref="s3://bucket/key",
            prev_record_hash="abc123",
            created_at=created_at,
        )

        hash2 = compute_record_hash_standalone(
            stream="security",
            seq_no=42,
            event_type="auth_login",
            payload_ref="s3://bucket/key",
            prev_record_hash="abc123",
            created_at=created_at,
        )

        assert hash1 == hash2

    def test_hash_changes_with_any_field(self):
        """Changing any field produces a different hash."""
        base_params = {
            "stream": "security",
            "seq_no": 42,
            "event_type": "auth_login",
            "payload_ref": "s3://bucket/key",
            "prev_record_hash": "abc123",
            "created_at": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        }

        base_hash = compute_record_hash_standalone(**base_params)

        # Test each field change produces different hash
        variations = [
            {"stream": "evidence"},
            {"seq_no": 43},
            {"event_type": "auth_logout"},
            {"payload_ref": "s3://bucket/other"},
            {"prev_record_hash": "def456"},
            {"created_at": datetime(2024, 1, 15, 10, 31, 0, tzinfo=UTC)},
        ]

        for variation in variations:
            params = {**base_params, **variation}
            varied_hash = compute_record_hash_standalone(**params)
            assert varied_hash != base_hash, f"Hash unchanged with {variation}"

    def test_hash_handles_null_prev_hash(self):
        """Hash computation works with None prev_record_hash."""
        created_at = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

        hash_with_none = compute_record_hash_standalone(
            stream="security",
            seq_no=1,
            event_type="auth_login",
            payload_ref="inline:test",
            prev_record_hash=None,
            created_at=created_at,
        )

        assert hash_with_none is not None
        assert len(hash_with_none) == 64


class TestAuditEventTypes:
    """Tests for audit event type enumeration."""

    def test_evidence_event_types_exist(self):
        """All evidence stream event types are defined."""
        evidence_events = [
            AuditEventType.DELIVERY_CREATED,
            AuditEventType.DELIVERY_DEPOSITED,
            AuditEventType.DELIVERY_NOTIFIED,
            AuditEventType.DELIVERY_ACCESSED,
            AuditEventType.DELIVERY_ACCEPTED,
            AuditEventType.DELIVERY_REFUSED,
            AuditEventType.DELIVERY_EXPIRED,
            AuditEventType.EVIDENCE_SEALED,
            AuditEventType.EVIDENCE_VERIFIED,
        ]
        assert all(e.value for e in evidence_events)

    def test_security_event_types_exist(self):
        """All security stream event types are defined."""
        security_events = [
            AuditEventType.AUTH_LOGIN,
            AuditEventType.AUTH_LOGOUT,
            AuditEventType.AUTH_FAILED,
            AuditEventType.AUTH_MFA_CHALLENGE,
            AuditEventType.AUTHZ_GRANTED,
            AuditEventType.AUTHZ_DENIED,
            AuditEventType.ADMIN_ACTION,
            AuditEventType.KEY_GENERATED,
            AuditEventType.KEY_ROTATED,
            AuditEventType.KEY_REVOKED,
            AuditEventType.PERMISSION_CHANGED,
        ]
        assert all(e.value for e in security_events)

    def test_ops_event_types_exist(self):
        """All operations stream event types are defined."""
        ops_events = [
            AuditEventType.CONFIG_CHANGED,
            AuditEventType.CONFIG_SNAPSHOT,
            AuditEventType.DEPLOYMENT_STARTED,
            AuditEventType.DEPLOYMENT_COMPLETED,
            AuditEventType.DEPLOYMENT_ROLLED_BACK,
            AuditEventType.BACKUP_STARTED,
            AuditEventType.BACKUP_COMPLETED,
            AuditEventType.BACKUP_VERIFIED,
            AuditEventType.DR_TEST_STARTED,
            AuditEventType.DR_TEST_COMPLETED,
            AuditEventType.MAINTENANCE_STARTED,
            AuditEventType.MAINTENANCE_COMPLETED,
        ]
        assert all(e.value for e in ops_events)


class TestChainVerificationResult:
    """Tests for ChainVerificationResult dataclass."""

    def test_valid_result_attributes(self):
        """Valid result has expected attributes."""
        result = ChainVerificationResult(
            valid=True,
            checked_records=100,
            first_seq_no=1,
            last_seq_no=100,
            errors=[],
        )

        assert result.valid is True
        assert result.checked_records == 100
        assert result.first_seq_no == 1
        assert result.last_seq_no == 100
        assert result.errors == []

    def test_invalid_result_with_errors(self):
        """Invalid result contains error descriptions."""
        errors = ["Hash mismatch at seq_no=5", "Chain break at seq_no=10"]
        result = ChainVerificationResult(
            valid=False,
            checked_records=15,
            first_seq_no=1,
            last_seq_no=15,
            errors=errors,
        )

        assert result.valid is False
        assert len(result.errors) == 2


class TestAuditLogEntry:
    """Tests for AuditLogEntry dataclass."""

    def test_entry_is_immutable(self):
        """AuditLogEntry cannot be modified after creation."""
        entry = AuditLogEntry(
            record_id=uuid4(),
            stream=AuditStream.SECURITY,
            seq_no=1,
            record_hash="a" * 64,
            prev_record_hash=None,
            event_type="auth_login",
            actor_type="user",
            actor_id="user-123",
            resource_type=None,
            resource_id=None,
            payload_ref="inline:test",
            summary=None,
            created_at=datetime.now(UTC),
        )

        with pytest.raises(AttributeError):
            entry.seq_no = 2  # type: ignore


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_session(
    existing_records: list,
    stream_filter: AuditStream | None = None,
) -> AsyncMock:
    """Create a mock SQLAlchemy async session.

    Args:
        existing_records: Records to return from queries.
        stream_filter: If set, return empty for queries on this stream.

    Returns:
        Mock async session.
    """
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        # For append, we query for the latest record in the stream
        if existing_records and stream_filter is None:
            result.scalar_one_or_none.return_value = existing_records[-1]
        else:
            result.scalar_one_or_none.return_value = None
        return result

    session.execute = mock_execute
    session.add = MagicMock()
    session.flush = AsyncMock()

    return session


def create_mock_session_for_verify(records: list) -> AsyncMock:
    """Create a mock session that returns records for verification.

    Args:
        records: Records to return from the query.

    Returns:
        Mock async session.
    """
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        scalars_result = MagicMock()
        scalars_result.all.return_value = records
        result.scalars.return_value = scalars_result
        return result

    session.execute = mock_execute
    return session


def create_mock_record(
    stream: AuditStream,
    seq_no: int,
    record_hash: str,
    prev_record_hash: str | None = None,
    event_type: str = "test_event",
    payload_ref: str = "inline:test:abc",
    created_at: datetime | None = None,
) -> MagicMock:
    """Create a mock AuditLogRecord.

    Args:
        stream: Audit stream.
        seq_no: Sequence number.
        record_hash: Hash of this record.
        prev_record_hash: Hash of previous record.
        event_type: Event type string.
        payload_ref: Payload reference.
        created_at: Creation timestamp.

    Returns:
        Mock record object.
    """
    record = MagicMock()
    record.record_id = uuid4()
    record.stream = stream
    record.seq_no = seq_no
    record.record_hash = record_hash
    record.prev_record_hash = prev_record_hash
    record.event_type = event_type
    record.payload_ref = payload_ref
    record.created_at = created_at or datetime.now(UTC)
    record.actor_type = None
    record.actor_id = None
    record.resource_type = None
    record.resource_id = None
    record.summary = None
    return record


def compute_test_hash(
    stream: AuditStream,
    seq_no: int,
    event_type: str,
    payload_ref: str,
    prev_record_hash: str | None,
    created_at: datetime,
) -> str:
    """Compute hash for test records using the same algorithm as the service.

    Args:
        stream: Audit stream.
        seq_no: Sequence number.
        event_type: Event type string.
        payload_ref: Payload reference.
        prev_record_hash: Hash of previous record.
        created_at: Creation timestamp.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    canonical = {
        "created_at": created_at.isoformat(),
        "event_type": event_type,
        "payload_ref": payload_ref,
        "prev_record_hash": prev_record_hash,
        "seq_no": seq_no,
        "stream": stream.value,
    }
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
