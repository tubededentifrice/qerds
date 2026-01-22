"""Tests for delivery lifecycle state machine service.

Tests cover:
- Valid state transitions
- Invalid transition rejection (monotonic enforcement)
- Evidence event generation for each transition
- Jurisdiction profile handling (fr_lre, eidas)
- 15-day acceptance window enforcement (REQ-F04)
- Expiry processing
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import ActorType, DeliveryState, EventType
from qerds.services.lifecycle import (
    DEFAULT_ACCEPTANCE_WINDOW_DAYS,
    JURISDICTION_PROFILES,
    DeliveryLifecycleService,
    DeliveryNotFoundError,
    TransitionResult,
)


class TestValidTransitions:
    """Tests for valid state transition mappings."""

    def test_draft_can_transition_to_deposited(self):
        """DRAFT can only transition to DEPOSITED."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.DEPOSITED)
        assert not service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.NOTIFIED)
        assert not service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.AVAILABLE)

    def test_deposited_can_transition_to_notified(self):
        """DEPOSITED can only transition to NOTIFIED."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.NOTIFIED)
        assert not service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.AVAILABLE)
        assert not service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.DRAFT)

    def test_notified_can_transition_to_available_or_failed(self):
        """NOTIFIED can transition to AVAILABLE or NOTIFICATION_FAILED."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(DeliveryState.NOTIFIED, DeliveryState.AVAILABLE)
        assert service.is_valid_transition(
            DeliveryState.NOTIFIED, DeliveryState.NOTIFICATION_FAILED
        )
        assert not service.is_valid_transition(DeliveryState.NOTIFIED, DeliveryState.ACCEPTED)

    def test_notification_failed_can_retry_or_override(self):
        """NOTIFICATION_FAILED can retry (NOTIFIED) or override to AVAILABLE."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(
            DeliveryState.NOTIFICATION_FAILED, DeliveryState.NOTIFIED
        )
        assert service.is_valid_transition(
            DeliveryState.NOTIFICATION_FAILED, DeliveryState.AVAILABLE
        )
        assert not service.is_valid_transition(
            DeliveryState.NOTIFICATION_FAILED, DeliveryState.ACCEPTED
        )

    def test_available_can_transition_to_terminal_states(self):
        """AVAILABLE can transition to ACCEPTED, REFUSED, or EXPIRED."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.ACCEPTED)
        assert service.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.REFUSED)
        assert service.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.EXPIRED)
        assert not service.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.RECEIVED)

    def test_accepted_can_transition_to_received(self):
        """ACCEPTED can only transition to RECEIVED."""
        service = DeliveryLifecycleService(MagicMock())
        assert service.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.RECEIVED)
        assert not service.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.REFUSED)
        assert not service.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.EXPIRED)

    def test_terminal_states_have_no_transitions(self):
        """REFUSED, RECEIVED, EXPIRED are terminal states."""
        service = DeliveryLifecycleService(MagicMock())

        terminal_states = [
            DeliveryState.REFUSED,
            DeliveryState.RECEIVED,
            DeliveryState.EXPIRED,
        ]

        all_states = list(DeliveryState)

        for terminal in terminal_states:
            assert service.is_terminal_state(terminal)
            for target in all_states:
                assert not service.is_valid_transition(terminal, target)

    def test_no_backwards_transitions(self):
        """Transitions are monotonic - no backwards movement."""
        service = DeliveryLifecycleService(MagicMock())

        # Cannot go backwards from DEPOSITED to DRAFT
        assert not service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.DRAFT)

        # Cannot go backwards from NOTIFIED to DEPOSITED
        assert not service.is_valid_transition(DeliveryState.NOTIFIED, DeliveryState.DEPOSITED)

        # Cannot go backwards from AVAILABLE to NOTIFIED
        assert not service.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.NOTIFIED)

        # Cannot go backwards from ACCEPTED to AVAILABLE
        assert not service.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.AVAILABLE)


class TestJurisdictionProfiles:
    """Tests for jurisdiction profile configuration."""

    def test_eidas_profile_exists(self):
        """eIDAS profile is configured with standard settings."""
        service = DeliveryLifecycleService(MagicMock())
        profile = service.get_jurisdiction_profile("eidas")

        assert profile.code == "eidas"
        assert profile.acceptance_window_days >= DEFAULT_ACCEPTANCE_WINDOW_DAYS
        assert isinstance(profile.redaction_profile, str)

    def test_fr_lre_profile_exists(self):
        """French LRE profile is configured with CPCE requirements."""
        service = DeliveryLifecycleService(MagicMock())
        profile = service.get_jurisdiction_profile("fr_lre")

        assert profile.code == "fr_lre"
        assert profile.acceptance_window_days >= 15  # CPCE minimum
        assert profile.requires_notification_delivery_proof is True
        redaction_lower = profile.redaction_profile.lower()
        assert "cpce" in redaction_lower or "lre" in redaction_lower

    def test_unknown_profile_raises_error(self):
        """Unknown profile code raises ValueError."""
        service = DeliveryLifecycleService(MagicMock())

        with pytest.raises(ValueError, match="Unknown jurisdiction profile"):
            service.get_jurisdiction_profile("unknown_profile")

    def test_all_profiles_have_minimum_acceptance_window(self):
        """All profiles meet minimum 15-day acceptance window."""
        for code, profile in JURISDICTION_PROFILES.items():
            assert profile.acceptance_window_days >= 15, f"Profile {code} has insufficient window"


class TestTransitionResult:
    """Tests for TransitionResult dataclass."""

    def test_success_result_has_event(self):
        """Successful transition includes evidence event."""
        event = MagicMock()
        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.DRAFT,
            new_state=DeliveryState.DEPOSITED,
            evidence_event=event,
            error=None,
        )

        assert result.success is True
        assert result.evidence_event is event
        assert result.error is None

    def test_failure_result_has_error(self):
        """Failed transition includes error message."""
        result = TransitionResult(
            success=False,
            previous_state=DeliveryState.DRAFT,
            new_state=DeliveryState.DRAFT,
            evidence_event=None,
            error="Invalid transition",
        )

        assert result.success is False
        assert result.evidence_event is None
        assert result.error == "Invalid transition"

    def test_result_is_immutable(self):
        """TransitionResult cannot be modified after creation."""
        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.DRAFT,
            new_state=DeliveryState.DEPOSITED,
            evidence_event=None,
            error=None,
        )

        with pytest.raises(AttributeError):
            result.success = False  # type: ignore


class TestTransitionExecution:
    """Tests for state transition execution."""

    @pytest.mark.asyncio
    async def test_deposit_transitions_from_draft(self):
        """deposit() transitions from DRAFT to DEPOSITED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref=str(uuid4()),
            content_hashes=["abc123", "def456"],
        )

        assert result.success is True
        assert result.previous_state == DeliveryState.DRAFT
        assert result.new_state == DeliveryState.DEPOSITED
        assert delivery.state == DeliveryState.DEPOSITED
        assert delivery.deposited_at is not None

    @pytest.mark.asyncio
    async def test_deposit_creates_evidence_event(self):
        """deposit() creates EVT_DEPOSITED evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
            content_hashes=["abc123"],
        )

        assert result.evidence_event is not None
        assert result.evidence_event.event_type == EventType.EVT_DEPOSITED
        assert result.evidence_event.actor_type == ActorType.SENDER
        assert result.evidence_event.actor_ref == "sender-123"

    @pytest.mark.asyncio
    async def test_notify_transitions_from_deposited(self):
        """notify() transitions from DEPOSITED to NOTIFIED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DEPOSITED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notify(
            delivery_id=delivery_id,
            notification_channel="email",
            notification_ref="msg-123",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.NOTIFIED
        assert delivery.notified_at is not None

    @pytest.mark.asyncio
    async def test_notification_failed_records_failure(self):
        """notification_failed() transitions to NOTIFICATION_FAILED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notification_failed(
            delivery_id=delivery_id,
            failure_reason="Mailbox full",
            bounce_type="soft",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.NOTIFICATION_FAILED
        assert result.evidence_event.event_type == EventType.EVT_NOTIFICATION_FAILED

    @pytest.mark.asyncio
    async def test_make_available_sets_deadline(self):
        """make_available() sets acceptance deadline based on jurisdiction."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        delivery.jurisdiction_profile = "fr_lre"
        session = create_mock_session(delivery)

        before = datetime.now(UTC)
        service = DeliveryLifecycleService(session)
        result = await service.make_available(delivery_id=delivery_id)
        after = datetime.now(UTC)

        assert result.success is True
        assert result.new_state == DeliveryState.AVAILABLE
        assert delivery.available_at is not None
        assert delivery.acceptance_deadline_at is not None

        # Deadline should be at least 15 days from now
        min_deadline = before + timedelta(days=15)
        max_deadline = after + timedelta(days=15, seconds=1)
        assert min_deadline <= delivery.acceptance_deadline_at <= max_deadline

    @pytest.mark.asyncio
    async def test_accept_transitions_from_available(self):
        """accept() transitions from AVAILABLE to ACCEPTED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        # Set deadline in the future
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.ACCEPTED
        assert delivery.completed_at is not None

    @pytest.mark.asyncio
    async def test_refuse_transitions_from_available(self):
        """refuse() transitions from AVAILABLE to REFUSED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.refuse(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
            refusal_reason="Not interested",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.REFUSED
        assert result.evidence_event.event_metadata.get("refusal_reason") == "Not interested"

    @pytest.mark.asyncio
    async def test_receive_transitions_from_accepted(self):
        """receive() transitions from ACCEPTED to RECEIVED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.ACCEPTED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.receive(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.RECEIVED
        assert result.evidence_event.event_type == EventType.EVT_RECEIVED

    @pytest.mark.asyncio
    async def test_expire_transitions_from_available(self):
        """expire() transitions from AVAILABLE to EXPIRED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.expire(delivery_id=delivery_id)

        assert result.success is True
        assert result.new_state == DeliveryState.EXPIRED
        assert result.evidence_event.event_type == EventType.EVT_EXPIRED


class TestInvalidTransitions:
    """Tests for invalid transition rejection."""

    @pytest.mark.asyncio
    async def test_invalid_transition_returns_failure(self):
        """Invalid transition returns failure result, not exception."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.AVAILABLE,  # Cannot go directly from DRAFT
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        assert result.success is False
        assert result.previous_state == DeliveryState.DRAFT
        assert result.new_state == DeliveryState.DRAFT  # Unchanged
        assert "Invalid transition" in result.error
        assert delivery.state == DeliveryState.DRAFT  # State unchanged

    @pytest.mark.asyncio
    async def test_terminal_state_rejects_transitions(self):
        """Terminal states reject all transitions."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.EXPIRED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.AVAILABLE,
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert result.success is False


class TestAcceptanceDeadlineEnforcement:
    """Tests for 15-day acceptance window enforcement (REQ-F04)."""

    @pytest.mark.asyncio
    async def test_accept_rejected_after_deadline(self):
        """accept() is rejected after acceptance deadline passes."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        # Deadline was yesterday
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is False
        assert "deadline has passed" in result.error.lower()
        assert delivery.state == DeliveryState.AVAILABLE  # State unchanged

    @pytest.mark.asyncio
    async def test_refuse_rejected_after_deadline(self):
        """refuse() is rejected after acceptance deadline passes."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.refuse(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is False
        assert "deadline has passed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_accept_allowed_before_deadline(self):
        """accept() is allowed when deadline is in the future."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        # Deadline is tomorrow
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True


class TestExpiryProcessing:
    """Tests for automated expiry processing."""

    @pytest.mark.asyncio
    async def test_check_and_expire_finds_expired_deliveries(self):
        """check_and_expire_deliveries() expires past-deadline deliveries."""
        # Create deliveries - one expired, one not
        expired_delivery = create_mock_delivery(uuid4(), DeliveryState.AVAILABLE)
        expired_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)

        current_delivery = create_mock_delivery(uuid4(), DeliveryState.AVAILABLE)
        current_delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)

        session = create_mock_session_for_expiry([expired_delivery])

        service = DeliveryLifecycleService(session)
        expired_ids = await service.check_and_expire_deliveries()

        assert len(expired_ids) == 1
        assert expired_ids[0] == expired_delivery.delivery_id
        assert expired_delivery.state == DeliveryState.EXPIRED

    @pytest.mark.asyncio
    async def test_check_and_expire_respects_batch_size(self):
        """check_and_expire_deliveries() respects batch_size parameter."""
        # Create a single expired delivery to test the batch query
        # The batch_size is tested by what the session returns, not actual DB limiting
        expired_delivery = create_mock_delivery(uuid4(), DeliveryState.AVAILABLE)
        expired_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)

        # Create a session that returns this delivery for both the batch query
        # and all subsequent get_delivery calls
        session = create_mock_session(expired_delivery)
        # Override execute to also handle the batch query pattern

        async def mock_execute_with_batch(query):
            result = MagicMock()
            # Support both single delivery lookup and batch query patterns
            result.scalar_one_or_none.return_value = expired_delivery
            scalars_result = MagicMock()
            scalars_result.all.return_value = [expired_delivery]
            result.scalars.return_value = scalars_result
            return result

        session.execute = mock_execute_with_batch

        service = DeliveryLifecycleService(session)
        expired_ids = await service.check_and_expire_deliveries(batch_size=100)

        # Only 1 delivery was returned by the query
        assert len(expired_ids) == 1
        assert expired_ids[0] == expired_delivery.delivery_id


class TestDeliveryNotFound:
    """Tests for delivery not found error handling."""

    @pytest.mark.asyncio
    async def test_transition_raises_not_found(self):
        """transition() raises error when delivery doesn't exist."""
        session = create_mock_session(None)  # No delivery found

        service = DeliveryLifecycleService(session)

        with pytest.raises(DeliveryNotFoundError) as exc:
            await service.transition(
                delivery_id=uuid4(),
                to_state=DeliveryState.DEPOSITED,
                actor_type=ActorType.SENDER,
                actor_ref="sender-123",
            )

        assert "not found" in str(exc.value).lower()


class TestEventMetadata:
    """Tests for evidence event metadata handling."""

    @pytest.mark.asyncio
    async def test_content_hashes_in_deposit_metadata(self):
        """deposit() includes content hashes in event metadata."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
            content_hashes=["hash1", "hash2"],
        )

        assert "content_hashes" in result.evidence_event.event_metadata
        assert result.evidence_event.event_metadata["content_hashes"] == ["hash1", "hash2"]

    @pytest.mark.asyncio
    async def test_notification_details_in_notify_metadata(self):
        """notify() includes notification details in event metadata."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DEPOSITED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notify(
            delivery_id=delivery_id,
            notification_channel="email",
            notification_ref="msg-abc123",
        )

        assert result.evidence_event.event_metadata["notification_channel"] == "email"
        assert result.evidence_event.event_metadata["notification_ref"] == "msg-abc123"

    @pytest.mark.asyncio
    async def test_acceptance_deadline_in_available_metadata(self):
        """make_available() includes deadline in event metadata."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(delivery_id=delivery_id)

        assert "acceptance_deadline" in result.evidence_event.event_metadata
        assert "acceptance_window_days" in result.evidence_event.event_metadata


class TestRetryFromNotificationFailed:
    """Tests for retry path from NOTIFICATION_FAILED state."""

    @pytest.mark.asyncio
    async def test_can_retry_notification(self):
        """Can transition from NOTIFICATION_FAILED back to NOTIFIED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFICATION_FAILED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notify(
            delivery_id=delivery_id,
            notification_channel="email",
            notification_ref="retry-msg-456",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.NOTIFIED

    @pytest.mark.asyncio
    async def test_can_override_to_available(self):
        """Can transition from NOTIFICATION_FAILED directly to AVAILABLE."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFICATION_FAILED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(
            delivery_id=delivery_id,
            event_metadata={"override_reason": "Manual verification"},
        )

        assert result.success is True
        assert result.new_state == DeliveryState.AVAILABLE


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_delivery(
    delivery_id,
    state: DeliveryState,
    jurisdiction_profile: str = "eidas",
):
    """Create a mock Delivery object.

    Args:
        delivery_id: UUID for the delivery.
        state: Initial state.
        jurisdiction_profile: Jurisdiction profile code.

    Returns:
        Mock delivery object.
    """
    delivery = MagicMock()
    delivery.delivery_id = delivery_id
    delivery.state = state
    delivery.jurisdiction_profile = jurisdiction_profile
    delivery.acceptance_deadline_at = None
    delivery.deposited_at = None
    delivery.notified_at = None
    delivery.available_at = None
    delivery.completed_at = None
    delivery.updated_at = None
    return delivery


def create_mock_session(delivery):
    """Create a mock SQLAlchemy async session.

    Args:
        delivery: Delivery to return from queries, or None.

    Returns:
        Mock async session.
    """
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = delivery
        return result

    session.execute = mock_execute
    session.add = MagicMock()
    session.flush = AsyncMock()

    return session


def create_mock_session_for_expiry(deliveries: list):
    """Create a mock session that returns deliveries for expiry check.

    The mock tracks which delivery should be returned for each get_delivery call
    based on the delivery_id in the query.

    Args:
        deliveries: List of deliveries to return from the query.

    Returns:
        Mock async session.
    """
    session = AsyncMock()
    call_count = 0

    async def mock_execute(query):
        nonlocal call_count
        result = MagicMock()

        # First call returns the list of deliveries for batch query
        # Subsequent calls return individual deliveries
        if call_count == 0:
            scalars_result = MagicMock()
            scalars_result.all.return_value = deliveries
            result.scalars.return_value = scalars_result
        else:
            # Return the specific delivery for get_delivery calls
            # Each delivery is looked up by index to match the expire() loop
            idx = (call_count - 1) % len(deliveries) if deliveries else 0
            result.scalar_one_or_none.return_value = deliveries[idx] if deliveries else None

        call_count += 1
        return result

    session.execute = mock_execute
    session.add = MagicMock()
    session.flush = AsyncMock()

    return session
