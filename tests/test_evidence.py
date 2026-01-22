"""Tests for evidence event generation service.

Tests cover:
- Event creation with all required fields
- Event retrieval by ID and delivery
- Input hashes for content integrity
- Actor identification tracking
- Policy snapshot references
- Pre-acceptance redaction profiles (REQ-F03)
- Timeline reconstruction for disputes (REQ-H10)
- Content access event recording (REQ-E02)
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import ActorType, EventType
from qerds.services.evidence import (
    ActorIdentification,
    CreateEventParams,
    DeliveryNotFoundError,
    EventData,
    EventNotFoundError,
    EvidenceService,
    apply_redaction,
    compute_content_hash,
    compute_metadata_hash,
    get_redaction_profile,
)


class TestEventDataClass:
    """Tests for EventData dataclass."""

    def test_event_data_is_immutable(self):
        """EventData cannot be modified after creation."""
        event = EventData(
            event_id=uuid4(),
            delivery_id=uuid4(),
            event_type=EventType.EVT_DEPOSITED,
            event_time=datetime.now(UTC),
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
            policy_snapshot_id=None,
            inputs_hashes={},
            event_metadata={},
        )

        with pytest.raises(AttributeError):
            event.event_type = EventType.EVT_ACCEPTED  # type: ignore

    def test_event_data_contains_all_required_fields(self):
        """EventData includes all fields required by spec."""
        event_id = uuid4()
        delivery_id = uuid4()
        policy_id = uuid4()
        event_time = datetime.now(UTC)

        event = EventData(
            event_id=event_id,
            delivery_id=delivery_id,
            event_type=EventType.EVT_DEPOSITED,
            event_time=event_time,
            actor_type=ActorType.SENDER,
            actor_ref="party-123",
            policy_snapshot_id=policy_id,
            inputs_hashes={"content": "abc123", "metadata": "def456"},
            event_metadata={"key": "value"},
        )

        # All required fields per spec
        assert event.event_id == event_id
        assert event.delivery_id == delivery_id
        assert event.event_type == EventType.EVT_DEPOSITED
        assert event.event_time == event_time
        assert event.actor_type == ActorType.SENDER
        assert event.actor_ref == "party-123"
        assert event.policy_snapshot_id == policy_id
        assert event.inputs_hashes == {"content": "abc123", "metadata": "def456"}
        assert event.event_metadata == {"key": "value"}


class TestActorIdentification:
    """Tests for ActorIdentification dataclass."""

    def test_basic_actor_identification(self):
        """Create basic actor identification with required fields."""
        actor = ActorIdentification(
            actor_type=ActorType.SENDER,
            actor_ref="party-123",
        )

        assert actor.actor_type == ActorType.SENDER
        assert actor.actor_ref == "party-123"
        assert actor.identity_proofing_ref is None
        assert actor.session_ref is None

    def test_full_actor_identification(self):
        """Create actor identification with all optional fields."""
        actor = ActorIdentification(
            actor_type=ActorType.RECIPIENT,
            actor_ref="party-456",
            identity_proofing_ref="proofing-789",
            session_ref="session-abc",
            ip_address_hash="deadbeef1234",
        )

        assert actor.identity_proofing_ref == "proofing-789"
        assert actor.session_ref == "session-abc"
        assert actor.ip_address_hash == "deadbeef1234"

    def test_actor_to_metadata(self):
        """to_metadata() converts to dict for storage."""
        actor = ActorIdentification(
            actor_type=ActorType.SENDER,
            actor_ref="party-123",
            identity_proofing_ref="proofing-xyz",
        )

        metadata = actor.to_metadata()

        assert metadata["actor_type"] == "sender"
        assert metadata["actor_ref"] == "party-123"
        assert metadata["identity_proofing_ref"] == "proofing-xyz"
        assert "session_ref" not in metadata  # None values excluded

    def test_system_actor(self):
        """System actor for automated actions."""
        actor = ActorIdentification(
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert actor.actor_type == ActorType.SYSTEM
        assert actor.actor_ref == "system"


class TestCreateEventParams:
    """Tests for CreateEventParams dataclass."""

    def test_minimal_params(self):
        """Create params with only required fields."""
        delivery_id = uuid4()
        actor = ActorIdentification(ActorType.SENDER, "sender-123")

        params = CreateEventParams(
            delivery_id=delivery_id,
            event_type=EventType.EVT_DEPOSITED,
            actor=actor,
        )

        assert params.delivery_id == delivery_id
        assert params.event_type == EventType.EVT_DEPOSITED
        assert params.actor == actor
        assert params.inputs_hashes == {}
        assert params.policy_snapshot_id is None
        assert params.event_metadata == {}
        assert params.event_time is None

    def test_full_params(self):
        """Create params with all fields populated."""
        delivery_id = uuid4()
        policy_id = uuid4()
        actor = ActorIdentification(ActorType.SENDER, "sender-123")
        event_time = datetime.now(UTC)

        params = CreateEventParams(
            delivery_id=delivery_id,
            event_type=EventType.EVT_DEPOSITED,
            actor=actor,
            inputs_hashes={"content": "hash1"},
            policy_snapshot_id=policy_id,
            event_metadata={"custom": "data"},
            event_time=event_time,
        )

        assert params.policy_snapshot_id == policy_id
        assert params.inputs_hashes == {"content": "hash1"}
        assert params.event_metadata == {"custom": "data"}
        assert params.event_time == event_time


class TestEvidenceServiceCreateEvent:
    """Tests for EvidenceService.create_event()."""

    @pytest.mark.asyncio
    async def test_create_event_success(self):
        """create_event() creates event with all fields."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.SENDER, "sender-123")

        event = await service.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_DEPOSITED,
                actor=actor,
                inputs_hashes={"content": "abc123"},
            )
        )

        assert event.delivery_id == delivery_id
        assert event.event_type == EventType.EVT_DEPOSITED
        assert event.actor_type == ActorType.SENDER
        assert event.actor_ref == "sender-123"
        assert event.inputs_hashes == {"content": "abc123"}

    @pytest.mark.asyncio
    async def test_create_event_with_policy_snapshot(self):
        """create_event() records policy snapshot reference."""
        delivery_id = uuid4()
        policy_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.SENDER, "sender-123")

        event = await service.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_DEPOSITED,
                actor=actor,
                policy_snapshot_id=policy_id,
            )
        )

        assert event.policy_snapshot_id == policy_id

    @pytest.mark.asyncio
    async def test_create_event_delivery_not_found(self):
        """create_event() raises error when delivery doesn't exist."""
        session = create_mock_session(None)  # No delivery found

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.SENDER, "sender-123")

        with pytest.raises(DeliveryNotFoundError) as exc:
            await service.create_event(
                CreateEventParams(
                    delivery_id=uuid4(),
                    event_type=EventType.EVT_DEPOSITED,
                    actor=actor,
                )
            )

        assert "not found" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_create_event_preserves_actor_metadata(self):
        """create_event() stores actor identification in metadata."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)

        service = EvidenceService(session)
        actor = ActorIdentification(
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-456",
            identity_proofing_ref="proofing-123",
            session_ref="session-abc",
        )

        event = await service.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_ACCEPTED,
                actor=actor,
            )
        )

        # Actor identification should be in metadata
        actor_info = event.event_metadata.get("actor_identification")
        assert actor_info is not None
        assert actor_info["actor_type"] == "recipient"
        assert actor_info["actor_ref"] == "recipient-456"
        assert actor_info["identity_proofing_ref"] == "proofing-123"

    @pytest.mark.asyncio
    async def test_create_event_with_custom_time(self):
        """create_event() can use custom event time for testing."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)
        custom_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.SYSTEM, "system")

        event = await service.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_EXPIRED,
                actor=actor,
                event_time=custom_time,
            )
        )

        assert event.event_time == custom_time

    @pytest.mark.asyncio
    async def test_create_event_merges_metadata(self):
        """create_event() merges custom metadata with actor info."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.SENDER, "sender-123")

        event = await service.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_DEPOSITED,
                actor=actor,
                event_metadata={"custom_key": "custom_value"},
            )
        )

        assert "actor_identification" in event.event_metadata
        assert event.event_metadata.get("custom_key") == "custom_value"


class TestEvidenceServiceGetEvent:
    """Tests for EvidenceService.get_event()."""

    @pytest.mark.asyncio
    async def test_get_event_success(self):
        """get_event() returns event by ID."""
        event_id = uuid4()
        delivery_id = uuid4()
        mock_event = create_mock_event(event_id, delivery_id)
        session = create_mock_session_for_event(mock_event)

        service = EvidenceService(session)
        event = await service.get_event(event_id)

        assert event.event_id == event_id
        assert event.delivery_id == delivery_id

    @pytest.mark.asyncio
    async def test_get_event_not_found(self):
        """get_event() raises error when event doesn't exist."""
        session = create_mock_session_for_event(None)

        service = EvidenceService(session)

        with pytest.raises(EventNotFoundError) as exc:
            await service.get_event(uuid4())

        assert "not found" in str(exc.value).lower()


class TestEvidenceServiceGetEvents:
    """Tests for EvidenceService.get_events()."""

    @pytest.mark.asyncio
    async def test_get_events_returns_chronological_order(self):
        """get_events() returns events in chronological order."""
        delivery_id = uuid4()
        time1 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        time2 = datetime(2024, 1, 1, 11, 0, 0, tzinfo=UTC)
        time3 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

        events = [
            create_mock_event(uuid4(), delivery_id, event_time=time1),
            create_mock_event(uuid4(), delivery_id, event_time=time2),
            create_mock_event(uuid4(), delivery_id, event_time=time3),
        ]
        session = create_mock_session_for_events(events)

        service = EvidenceService(session)
        result = await service.get_events(delivery_id)

        assert len(result) == 3
        # Events should be in chronological order
        assert result[0].event_time == time1
        assert result[1].event_time == time2
        assert result[2].event_time == time3

    @pytest.mark.asyncio
    async def test_get_events_empty_for_no_events(self):
        """get_events() returns empty list when no events exist."""
        session = create_mock_session_for_events([])

        service = EvidenceService(session)
        result = await service.get_events(uuid4())

        assert result == []


class TestEvidenceServiceRecordContentAccess:
    """Tests for EvidenceService.record_content_access()."""

    @pytest.mark.asyncio
    async def test_record_content_access_creates_event(self):
        """record_content_access() creates EVT_CONTENT_ACCESSED event."""
        delivery_id = uuid4()
        content_id = uuid4()
        delivery = create_mock_delivery(delivery_id)
        session = create_mock_session(delivery)

        service = EvidenceService(session)
        actor = ActorIdentification(ActorType.RECIPIENT, "recipient-123")

        event = await service.record_content_access(
            delivery_id=delivery_id,
            actor=actor,
            content_object_ids=[content_id],
            access_type="download",
        )

        assert event.event_type == EventType.EVT_CONTENT_ACCESSED
        assert "content_object_ids" in event.event_metadata
        assert event.event_metadata["access_type"] == "download"


class TestHashFunctions:
    """Tests for hash utility functions."""

    def test_compute_content_hash(self):
        """compute_content_hash() returns SHA-256 hex digest."""
        content = b"Hello, World!"
        result = compute_content_hash(content)

        assert len(result) == 64  # SHA-256 hex is 64 chars
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_content_hash_deterministic(self):
        """compute_content_hash() returns same hash for same content."""
        content = b"Test content"
        hash1 = compute_content_hash(content)
        hash2 = compute_content_hash(content)

        assert hash1 == hash2

    def test_compute_content_hash_different_for_different_content(self):
        """compute_content_hash() returns different hash for different content."""
        hash1 = compute_content_hash(b"Content A")
        hash2 = compute_content_hash(b"Content B")

        assert hash1 != hash2

    def test_compute_metadata_hash(self):
        """compute_metadata_hash() returns SHA-256 of canonical JSON."""
        metadata = {"key": "value", "number": 42}
        result = compute_metadata_hash(metadata)

        assert len(result) == 64

    def test_compute_metadata_hash_order_independent(self):
        """compute_metadata_hash() is independent of dict key order."""
        metadata1 = {"a": 1, "b": 2}
        metadata2 = {"b": 2, "a": 1}

        hash1 = compute_metadata_hash(metadata1)
        hash2 = compute_metadata_hash(metadata2)

        assert hash1 == hash2


class TestRedactionProfiles:
    """Tests for pre-acceptance redaction profiles (REQ-F03)."""

    def test_eidas_default_profile_exists(self):
        """eIDAS default profile allows full disclosure."""
        profile = get_redaction_profile("eidas_default")

        assert profile["hide_sender_identity"] is False
        assert profile["hide_sender_details"] is False
        assert profile["hide_subject"] is False

    def test_fr_lre_cpce_profile_exists(self):
        """French LRE/CPCE profile hides sender before acceptance."""
        profile = get_redaction_profile("fr_lre_cpce")

        # CPCE requires hiding sender identity before acceptance
        assert profile["hide_sender_identity"] is True
        assert profile["hide_sender_details"] is True
        assert profile["hide_content_metadata"] is True

    def test_unknown_profile_raises_error(self):
        """Unknown profile code raises ValueError."""
        with pytest.raises(ValueError, match="Unknown redaction profile"):
            get_redaction_profile("unknown_profile")

    def test_apply_redaction_post_acceptance(self):
        """apply_redaction() returns full data when accepted."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean@example.com",
            "subject": "Important document",
        }

        result = apply_redaction(data, "fr_lre_cpce", is_accepted=True)

        # Post-acceptance: full disclosure
        assert result["sender_name"] == "Jean Dupont"
        assert result["sender_email"] == "jean@example.com"
        assert result["subject"] == "Important document"

    def test_apply_redaction_pre_acceptance_fr_lre(self):
        """apply_redaction() hides sender identity pre-acceptance for FR LRE."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean@example.com",
            "subject": "Important document",
            "original_filename": "contract.pdf",
        }

        result = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        # Pre-acceptance with CPCE: sender hidden
        assert result["sender_name"] == "[REDACTED]"
        assert result["sender_email"] == "[REDACTED]"
        assert result["subject"] == "Important document"  # Subject allowed
        assert result["original_filename"] == "[REDACTED]"  # Content metadata hidden

    def test_apply_redaction_pre_acceptance_eidas(self):
        """apply_redaction() allows full disclosure for eIDAS."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean@example.com",
            "subject": "Important document",
        }

        result = apply_redaction(data, "eidas_default", is_accepted=False)

        # eIDAS default: full disclosure even pre-acceptance
        assert result["sender_name"] == "Jean Dupont"
        assert result["sender_email"] == "jean@example.com"

    def test_apply_redaction_does_not_modify_original(self):
        """apply_redaction() returns a new dict, not modifying original."""
        data = {"sender_name": "Jean Dupont"}

        result = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        assert data["sender_name"] == "Jean Dupont"  # Original unchanged
        assert result["sender_name"] == "[REDACTED]"  # Result redacted


class TestEventTypeCatalog:
    """Tests for evidence event type completeness."""

    def test_all_required_event_types_exist(self):
        """All event types from spec are defined."""
        required_types = [
            "EVT_DEPOSITED",
            "EVT_NOTIFICATION_SENT",
            "EVT_NOTIFICATION_FAILED",
            "EVT_CONTENT_AVAILABLE",
            "EVT_ACCEPTED",
            "EVT_REFUSED",
            "EVT_RECEIVED",
            "EVT_EXPIRED",
            "EVT_CONTENT_ACCESSED",
        ]

        for type_name in required_types:
            assert hasattr(EventType, type_name), f"Missing event type: {type_name}"


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_delivery(delivery_id):
    """Create a mock Delivery object."""
    delivery = MagicMock()
    delivery.delivery_id = delivery_id
    return delivery


def create_mock_session(delivery):
    """Create a mock async session that returns delivery for validation."""
    session = AsyncMock()

    # Track added events for inspection
    session._added_events = []

    async def mock_execute(query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = delivery
        return result

    def mock_add(obj):
        # If it's an EvidenceEvent, store it and assign an ID
        if hasattr(obj, "event_id"):
            obj.event_id = uuid4()
        session._added_events.append(obj)

    session.execute = mock_execute
    session.add = mock_add
    session.flush = AsyncMock()

    return session


def create_mock_event(
    event_id,
    delivery_id,
    event_type=EventType.EVT_DEPOSITED,
    event_time=None,
    event_metadata=None,
):
    """Create a mock EvidenceEvent object."""
    event = MagicMock()
    event.event_id = event_id
    event.delivery_id = delivery_id
    event.event_type = event_type
    event.event_time = event_time or datetime.now(UTC)
    event.actor_type = ActorType.SENDER
    event.actor_ref = "sender-123"
    event.policy_snapshot_id = None
    event.event_metadata = event_metadata or {}
    return event


def create_mock_session_for_event(event):
    """Create a mock session that returns a single event."""
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = event
        return result

    session.execute = mock_execute
    return session


def create_mock_session_for_events(events):
    """Create a mock session that returns a list of events."""
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        scalars_result = MagicMock()
        scalars_result.all.return_value = events
        result.scalars.return_value = scalars_result
        return result

    session.execute = mock_execute
    return session
