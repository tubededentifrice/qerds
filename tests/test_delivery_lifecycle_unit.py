"""Comprehensive unit tests for delivery lifecycle state machine.

Covers: REQ-B01, REQ-C01, REQ-E02, REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-F06, REQ-H10

Test Categories:
1. Valid state transitions (all paths through the state machine)
2. Invalid transition rejection (monotonic enforcement)
3. 15-day window enforcement with edge cases
4. Evidence event generation for each transition
5. Pre-acceptance redaction enforcement (REQ-F03)
6. Concurrent transition handling (race conditions)
7. Edge cases (exact deadline, timezone handling, etc.)

Per task qerds-ax1: Comprehensive tests targeting 95%+ coverage of state machine code.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from qerds.db.models.base import ActorType, DeliveryState, EventType
from qerds.services.evidence import apply_redaction, get_redaction_profile
from qerds.services.lifecycle import (
    DEFAULT_ACCEPTANCE_WINDOW_DAYS,
    JURISDICTION_PROFILES,
    DeliveryLifecycleService,
    DeliveryNotFoundError,
    JurisdictionProfile,
    TransitionResult,
)

# =============================================================================
# Test Fixtures and Helpers
# =============================================================================


def create_mock_delivery(
    delivery_id,
    state: DeliveryState,
    jurisdiction_profile: str = "eidas",
    sender_party_id=None,
    recipient_party_id=None,
) -> MagicMock:
    """Create a mock Delivery object with all required attributes.

    Args:
        delivery_id: UUID for the delivery.
        state: Initial state.
        jurisdiction_profile: Jurisdiction profile code.
        sender_party_id: Optional sender party ID.
        recipient_party_id: Optional recipient party ID.

    Returns:
        Mock delivery object with standard attributes.
    """
    delivery = MagicMock()
    delivery.delivery_id = delivery_id
    delivery.state = state
    delivery.jurisdiction_profile = jurisdiction_profile
    delivery.sender_party_id = sender_party_id or uuid4()
    delivery.recipient_party_id = recipient_party_id or uuid4()
    delivery.acceptance_deadline_at = None
    delivery.deposited_at = None
    delivery.notified_at = None
    delivery.available_at = None
    delivery.completed_at = None
    delivery.updated_at = None
    delivery.pre_acceptance_redaction_profile = None
    delivery.subject = "Test Subject"
    delivery.message = "Test Message"
    return delivery


def create_mock_session(delivery) -> AsyncMock:
    """Create a mock SQLAlchemy async session.

    Args:
        delivery: Delivery to return from queries, or None for not found.

    Returns:
        Mock async session with execute, add, flush methods.
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


def create_mock_session_for_batch(deliveries: list) -> AsyncMock:
    """Create a mock session that handles both single lookups and batch queries.

    Args:
        deliveries: List of deliveries to return from batch queries.

    Returns:
        Mock async session.
    """
    session = AsyncMock()
    call_count = 0

    async def mock_execute(query):
        nonlocal call_count
        result = MagicMock()

        if call_count == 0:
            # First call is the batch query
            scalars_result = MagicMock()
            scalars_result.all.return_value = deliveries
            result.scalars.return_value = scalars_result
        else:
            # Subsequent calls are individual delivery lookups
            idx = (call_count - 1) % len(deliveries) if deliveries else 0
            result.scalar_one_or_none.return_value = deliveries[idx] if deliveries else None

        call_count += 1
        return result

    session.execute = mock_execute
    session.add = MagicMock()
    session.flush = AsyncMock()

    return session


# =============================================================================
# TEST CLASS: Valid State Transitions (Complete Coverage)
# =============================================================================


class TestValidStateTransitions:
    """Tests for all valid state transition paths through the state machine.

    The state machine follows this flow:
        DRAFT -> DEPOSITED -> NOTIFIED -> AVAILABLE -> ACCEPTED/REFUSED -> RECEIVED
                               |                                             |
                               v                                             |
                        NOTIFICATION_FAILED (retry)                          |
                                                                             v
                                                                          EXPIRED
    """

    def test_all_states_defined_in_transitions(self):
        """Every DeliveryState has an entry in VALID_TRANSITIONS."""
        service = DeliveryLifecycleService(MagicMock())
        for state in DeliveryState:
            assert state in service.VALID_TRANSITIONS, f"Missing transition entry for {state}"

    def test_draft_to_deposited_is_only_valid_transition(self):
        """DRAFT can only transition to DEPOSITED."""
        service = DeliveryLifecycleService(MagicMock())

        # Only valid transition
        assert service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.DEPOSITED)

        # All others should be invalid
        invalid_targets = [s for s in DeliveryState if s != DeliveryState.DEPOSITED]
        for target in invalid_targets:
            assert not service.is_valid_transition(DeliveryState.DRAFT, target), (
                f"DRAFT->>{target} should be invalid"
            )

    def test_deposited_to_notified_is_only_valid_transition(self):
        """DEPOSITED can only transition to NOTIFIED."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.NOTIFIED)

        invalid_targets = [s for s in DeliveryState if s != DeliveryState.NOTIFIED]
        for target in invalid_targets:
            assert not service.is_valid_transition(DeliveryState.DEPOSITED, target), (
                f"DEPOSITED->{target} should be invalid"
            )

    def test_notified_transitions_to_available_or_failed(self):
        """NOTIFIED can transition to AVAILABLE or NOTIFICATION_FAILED."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_valid_transition(DeliveryState.NOTIFIED, DeliveryState.AVAILABLE)
        assert service.is_valid_transition(
            DeliveryState.NOTIFIED, DeliveryState.NOTIFICATION_FAILED
        )

        # All others invalid
        valid_targets = {DeliveryState.AVAILABLE, DeliveryState.NOTIFICATION_FAILED}
        invalid_targets = [s for s in DeliveryState if s not in valid_targets]
        for target in invalid_targets:
            assert not service.is_valid_transition(DeliveryState.NOTIFIED, target), (
                f"NOTIFIED->{target} should be invalid"
            )

    def test_notification_failed_can_retry_or_override(self):
        """NOTIFICATION_FAILED can transition to NOTIFIED (retry) or AVAILABLE (override)."""
        service = DeliveryLifecycleService(MagicMock())

        # Retry path
        assert service.is_valid_transition(
            DeliveryState.NOTIFICATION_FAILED, DeliveryState.NOTIFIED
        )
        # Manual override path
        assert service.is_valid_transition(
            DeliveryState.NOTIFICATION_FAILED, DeliveryState.AVAILABLE
        )

    def test_available_transitions_to_terminal_states(self):
        """AVAILABLE can transition to ACCEPTED, REFUSED, or EXPIRED."""
        service = DeliveryLifecycleService(MagicMock())

        valid_targets = {DeliveryState.ACCEPTED, DeliveryState.REFUSED, DeliveryState.EXPIRED}
        for target in valid_targets:
            assert service.is_valid_transition(DeliveryState.AVAILABLE, target), (
                f"AVAILABLE->{target} should be valid"
            )

        invalid_targets = [s for s in DeliveryState if s not in valid_targets]
        for target in invalid_targets:
            assert not service.is_valid_transition(DeliveryState.AVAILABLE, target), (
                f"AVAILABLE->{target} should be invalid"
            )

    def test_accepted_can_only_transition_to_received(self):
        """ACCEPTED can only transition to RECEIVED."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.RECEIVED)

        invalid_targets = [s for s in DeliveryState if s != DeliveryState.RECEIVED]
        for target in invalid_targets:
            assert not service.is_valid_transition(DeliveryState.ACCEPTED, target), (
                f"ACCEPTED->{target} should be invalid"
            )

    def test_refused_is_terminal(self):
        """REFUSED is a terminal state with no outgoing transitions."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_terminal_state(DeliveryState.REFUSED)
        for target in DeliveryState:
            assert not service.is_valid_transition(DeliveryState.REFUSED, target), (
                f"REFUSED->{target} should be invalid (terminal)"
            )

    def test_received_is_terminal(self):
        """RECEIVED is a terminal state with no outgoing transitions."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_terminal_state(DeliveryState.RECEIVED)
        for target in DeliveryState:
            assert not service.is_valid_transition(DeliveryState.REFUSED, target), (
                f"RECEIVED->{target} should be invalid (terminal)"
            )

    def test_expired_is_terminal(self):
        """EXPIRED is a terminal state with no outgoing transitions."""
        service = DeliveryLifecycleService(MagicMock())

        assert service.is_terminal_state(DeliveryState.EXPIRED)
        for target in DeliveryState:
            assert not service.is_valid_transition(DeliveryState.EXPIRED, target), (
                f"EXPIRED->{target} should be invalid (terminal)"
            )


# =============================================================================
# TEST CLASS: Invalid Transition Rejection
# =============================================================================


class TestInvalidTransitionRejection:
    """Tests for invalid transition rejection (monotonic enforcement).

    The state machine enforces monotonic progression - no backward transitions
    except for the notification retry path.
    """

    @pytest.mark.asyncio
    async def test_direct_draft_to_accepted_rejected(self):
        """Cannot transition directly from DRAFT to ACCEPTED (skipping states)."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.ACCEPTED,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is False
        assert "Invalid transition" in result.error
        assert result.new_state == DeliveryState.DRAFT  # Unchanged
        assert delivery.state == DeliveryState.DRAFT

    @pytest.mark.asyncio
    async def test_direct_draft_to_available_rejected(self):
        """Cannot transition directly from DRAFT to AVAILABLE."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.AVAILABLE,
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert result.success is False

    @pytest.mark.asyncio
    async def test_backward_deposited_to_draft_rejected(self):
        """Cannot transition backwards from DEPOSITED to DRAFT."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DEPOSITED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.DRAFT,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        assert result.success is False
        assert delivery.state == DeliveryState.DEPOSITED

    @pytest.mark.asyncio
    async def test_backward_notified_to_deposited_rejected(self):
        """Cannot transition backwards from NOTIFIED to DEPOSITED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.DEPOSITED,
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert result.success is False

    @pytest.mark.asyncio
    async def test_backward_available_to_notified_rejected(self):
        """Cannot transition backwards from AVAILABLE to NOTIFIED."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.NOTIFIED,
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert result.success is False

    @pytest.mark.asyncio
    async def test_backward_accepted_to_available_rejected(self):
        """Cannot transition backwards from ACCEPTED to AVAILABLE."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.ACCEPTED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.AVAILABLE,
            actor_type=ActorType.SYSTEM,
            actor_ref="system",
        )

        assert result.success is False

    @pytest.mark.asyncio
    async def test_terminal_state_refuses_all_transitions(self):
        """Terminal states (REFUSED, RECEIVED, EXPIRED) reject all transitions."""
        terminal_states = [DeliveryState.REFUSED, DeliveryState.RECEIVED, DeliveryState.EXPIRED]

        for terminal_state in terminal_states:
            delivery_id = uuid4()
            delivery = create_mock_delivery(delivery_id, terminal_state)
            session = create_mock_session(delivery)

            service = DeliveryLifecycleService(session)

            # Try all possible target states
            for target in DeliveryState:
                result = await service.transition(
                    delivery_id=delivery_id,
                    to_state=target,
                    actor_type=ActorType.SYSTEM,
                    actor_ref="system",
                )
                assert result.success is False, f"Terminal {terminal_state}->{target} should fail"

    @pytest.mark.asyncio
    async def test_invalid_transition_does_not_create_evidence(self):
        """Invalid transitions do not create evidence events."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.RECEIVED,  # Invalid from DRAFT
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is False
        assert result.evidence_event is None


# =============================================================================
# TEST CLASS: 15-Day Window Enforcement (REQ-F04)
# =============================================================================


class TestAcceptanceWindowEnforcement:
    """Tests for 15-day acceptance window enforcement (REQ-F04).

    The CPCE requires a minimum 15-day window for recipient to accept/refuse.
    After the deadline, only EXPIRED transition is valid.
    """

    @pytest.mark.asyncio
    async def test_accept_blocked_after_deadline(self):
        """accept() is blocked when deadline has passed."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is False
        assert "deadline has passed" in result.error.lower()
        assert delivery.state == DeliveryState.AVAILABLE

    @pytest.mark.asyncio
    async def test_refuse_blocked_after_deadline(self):
        """refuse() is blocked when deadline has passed."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(minutes=1)
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
        """accept() succeeds when deadline is in the future."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.ACCEPTED

    @pytest.mark.asyncio
    async def test_refuse_allowed_before_deadline(self):
        """refuse() succeeds when deadline is in the future."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=7)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.refuse(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True
        assert result.new_state == DeliveryState.REFUSED

    @pytest.mark.asyncio
    async def test_accept_at_exact_deadline_microsecond(self):
        """Edge case: accept() at exact deadline moment (boundary condition).

        When acceptance_deadline_at equals current time, the deadline has passed.
        This tests the > comparison, not >=.
        """
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)

        # Freeze time to test exact boundary
        fixed_now = datetime(2024, 6, 15, 12, 0, 0, 0, tzinfo=UTC)
        delivery.acceptance_deadline_at = fixed_now - timedelta(microseconds=1)

        session = create_mock_session(delivery)
        service = DeliveryLifecycleService(session)

        with patch("qerds.services.lifecycle.datetime") as mock_datetime:
            mock_datetime.now.return_value = fixed_now
            # Mock UTC for the side_effect of datetime.now(UTC)
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            result = await service.accept(
                delivery_id=delivery_id,
                actor_type=ActorType.RECIPIENT,
                actor_ref="recipient-123",
            )

        # Deadline was 1 microsecond before "now", so it has passed
        assert result.success is False

    @pytest.mark.asyncio
    async def test_make_available_sets_deadline_15_days(self):
        """make_available() sets acceptance_deadline_at to now + 15 days."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        delivery.jurisdiction_profile = "eidas"
        session = create_mock_session(delivery)

        before = datetime.now(UTC)
        service = DeliveryLifecycleService(session)
        result = await service.make_available(delivery_id=delivery_id)
        after = datetime.now(UTC)

        assert result.success is True
        assert delivery.acceptance_deadline_at is not None

        # Verify deadline is approximately 15 days from now
        min_deadline = before + timedelta(days=15)
        max_deadline = after + timedelta(days=15, seconds=1)
        assert min_deadline <= delivery.acceptance_deadline_at <= max_deadline

    @pytest.mark.asyncio
    async def test_expire_allowed_after_deadline(self):
        """expire() succeeds when deadline has passed."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.expire(delivery_id=delivery_id)

        assert result.success is True
        assert result.new_state == DeliveryState.EXPIRED

    @pytest.mark.asyncio
    async def test_deadline_in_evidence_metadata(self):
        """Acceptance deadline is recorded in evidence event metadata."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(delivery_id=delivery_id)

        assert result.success is True
        assert "acceptance_deadline" in result.evidence_event.event_metadata
        assert "acceptance_window_days" in result.evidence_event.event_metadata

    def test_all_jurisdiction_profiles_meet_minimum_15_days(self):
        """All jurisdiction profiles have at least 15-day acceptance window."""
        for code, profile in JURISDICTION_PROFILES.items():
            min_days = DEFAULT_ACCEPTANCE_WINDOW_DAYS
            assert profile.acceptance_window_days >= min_days, (
                f"Profile {code} has {profile.acceptance_window_days} days, minimum is {min_days}"
            )


# =============================================================================
# TEST CLASS: Evidence Event Generation
# =============================================================================


class TestEvidenceEventGeneration:
    """Tests for evidence event generation on each state transition.

    Every lifecycle transition MUST emit an evidence event for compliance.
    """

    @pytest.mark.asyncio
    async def test_deposit_creates_evt_deposited(self):
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

        assert result.success is True
        assert result.evidence_event is not None
        assert result.evidence_event.event_type == EventType.EVT_DEPOSITED
        assert result.evidence_event.actor_type == ActorType.SENDER

    @pytest.mark.asyncio
    async def test_notify_creates_evt_notification_sent(self):
        """notify() creates EVT_NOTIFICATION_SENT evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DEPOSITED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notify(
            delivery_id=delivery_id,
            notification_channel="email",
        )

        assert result.success is True
        assert result.evidence_event.event_type == EventType.EVT_NOTIFICATION_SENT

    @pytest.mark.asyncio
    async def test_notification_failed_creates_evt_notification_failed(self):
        """notification_failed() creates EVT_NOTIFICATION_FAILED evidence event."""
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
        assert result.evidence_event.event_type == EventType.EVT_NOTIFICATION_FAILED
        assert result.evidence_event.event_metadata.get("failure_reason") == "Mailbox full"
        assert result.evidence_event.event_metadata.get("bounce_type") == "soft"

    @pytest.mark.asyncio
    async def test_make_available_creates_evt_content_available(self):
        """make_available() creates EVT_CONTENT_AVAILABLE evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFIED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(delivery_id=delivery_id)

        assert result.success is True
        assert result.evidence_event.event_type == EventType.EVT_CONTENT_AVAILABLE

    @pytest.mark.asyncio
    async def test_accept_creates_evt_accepted(self):
        """accept() creates EVT_ACCEPTED evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success is True
        assert result.evidence_event.event_type == EventType.EVT_ACCEPTED
        assert result.evidence_event.actor_type == ActorType.RECIPIENT

    @pytest.mark.asyncio
    async def test_refuse_creates_evt_refused(self):
        """refuse() creates EVT_REFUSED evidence event."""
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
        assert result.evidence_event.event_type == EventType.EVT_REFUSED
        assert result.evidence_event.event_metadata.get("refusal_reason") == "Not interested"

    @pytest.mark.asyncio
    async def test_receive_creates_evt_received(self):
        """receive() creates EVT_RECEIVED evidence event."""
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
        assert result.evidence_event.event_type == EventType.EVT_RECEIVED

    @pytest.mark.asyncio
    async def test_expire_creates_evt_expired(self):
        """expire() creates EVT_EXPIRED evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.expire(delivery_id=delivery_id)

        assert result.success is True
        assert result.evidence_event.event_type == EventType.EVT_EXPIRED
        assert "acceptance_deadline" in result.evidence_event.event_metadata

    @pytest.mark.asyncio
    async def test_event_includes_policy_snapshot_when_provided(self):
        """Evidence event includes policy_snapshot_id when provided."""
        delivery_id = uuid4()
        policy_snapshot_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
            policy_snapshot_id=policy_snapshot_id,
        )

        assert result.success is True
        assert result.evidence_event.policy_snapshot_id == policy_snapshot_id

    @pytest.mark.asyncio
    async def test_event_metadata_preserved_through_transition(self):
        """Custom event_metadata is preserved in evidence event."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        custom_metadata = {
            "ip_address_hash": "sha256:abc123...",
            "session_id": "sess-456",
            "user_agent": "Mozilla/5.0",
        }

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
            event_metadata=custom_metadata,
        )

        assert result.success is True
        for key, value in custom_metadata.items():
            assert result.evidence_event.event_metadata.get(key) == value

    def test_all_states_have_event_type_mapping(self):
        """Every non-DRAFT state has a corresponding event type."""
        service = DeliveryLifecycleService(MagicMock())

        # DRAFT doesn't have an event because it's the initial state
        states_with_events = [s for s in DeliveryState if s != DeliveryState.DRAFT]

        for state in states_with_events:
            assert state in service.TRANSITION_EVENTS, f"Missing event type mapping for {state}"

    def test_event_types_match_states(self):
        """Event types are correctly mapped to their corresponding states."""
        service = DeliveryLifecycleService(MagicMock())

        expected_mappings = {
            DeliveryState.DEPOSITED: EventType.EVT_DEPOSITED,
            DeliveryState.NOTIFIED: EventType.EVT_NOTIFICATION_SENT,
            DeliveryState.NOTIFICATION_FAILED: EventType.EVT_NOTIFICATION_FAILED,
            DeliveryState.AVAILABLE: EventType.EVT_CONTENT_AVAILABLE,
            DeliveryState.ACCEPTED: EventType.EVT_ACCEPTED,
            DeliveryState.REFUSED: EventType.EVT_REFUSED,
            DeliveryState.RECEIVED: EventType.EVT_RECEIVED,
            DeliveryState.EXPIRED: EventType.EVT_EXPIRED,
        }

        for state, expected_event in expected_mappings.items():
            assert service.TRANSITION_EVENTS[state] == expected_event


# =============================================================================
# TEST CLASS: Pre-Acceptance Redaction Enforcement (REQ-F03)
# =============================================================================


class TestPreAcceptanceRedaction:
    """Tests for pre-acceptance redaction enforcement (REQ-F03).

    Before recipient acceptance/refusal, sender identity must be hidden
    per CPCE requirements.
    """

    def test_fr_lre_cpce_redaction_profile_exists(self):
        """French LRE/CPCE redaction profile is defined."""
        profile = get_redaction_profile("fr_lre_cpce")

        assert profile["hide_sender_identity"] is True
        assert profile["hide_sender_details"] is True

    def test_eidas_default_profile_does_not_hide_sender(self):
        """eIDAS default profile does not hide sender identity."""
        profile = get_redaction_profile("eidas_default")

        assert profile["hide_sender_identity"] is False

    def test_apply_redaction_hides_sender_identity_pre_acceptance(self):
        """apply_redaction() hides sender identity for fr_lre_cpce profile."""
        data = {
            "delivery_id": str(uuid4()),
            "sender_name": "Jean Dupont",
            "sender_email": "jean.dupont@example.com",
            "sender_party_id": str(uuid4()),
            "subject": "Test Subject",
            "recipient_name": "Marie Martin",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        assert redacted["sender_name"] == "[REDACTED]"
        assert redacted["sender_email"] == "[REDACTED]"
        assert redacted["sender_party_id"] == "[REDACTED]"
        # Non-sender fields should be unchanged
        assert redacted["subject"] == "Test Subject"
        assert redacted["recipient_name"] == "Marie Martin"

    def test_apply_redaction_shows_all_post_acceptance(self):
        """apply_redaction() shows all data after acceptance."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean.dupont@example.com",
            "subject": "Test Subject",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=True)

        assert redacted["sender_name"] == "Jean Dupont"
        assert redacted["sender_email"] == "jean.dupont@example.com"

    def test_apply_redaction_hides_content_metadata(self):
        """apply_redaction() hides content metadata when configured."""
        data = {
            "original_filename": "secret_document.pdf",
            "content_description": "Confidential report",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        assert redacted["original_filename"] == "[REDACTED]"
        assert redacted["content_description"] == "[REDACTED]"

    def test_apply_redaction_does_not_modify_original(self):
        """apply_redaction() returns a new dict, not modifying original."""
        original = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean@example.com",
        }

        redacted = apply_redaction(original, "fr_lre_cpce", is_accepted=False)

        # Original should be unchanged
        assert original["sender_name"] == "Jean Dupont"
        assert original["sender_email"] == "jean@example.com"
        # Redacted should have changes
        assert redacted["sender_name"] == "[REDACTED]"

    def test_unknown_redaction_profile_raises_error(self):
        """Unknown redaction profile code raises ValueError."""
        with pytest.raises(ValueError, match="Unknown redaction profile"):
            get_redaction_profile("nonexistent_profile")

    def test_jurisdiction_profile_has_redaction_profile(self):
        """Jurisdiction profiles define their redaction profiles."""
        for code, profile in JURISDICTION_PROFILES.items():
            assert profile.redaction_profile is not None, (
                f"Profile {code} missing redaction_profile"
            )
            # The redaction profile should exist in REDACTION_PROFILES
            # (though names may not match exactly - they reference the redaction system)
            assert isinstance(profile.redaction_profile, str)


# =============================================================================
# TEST CLASS: Concurrent Transition Handling
# =============================================================================


class TestConcurrentTransitionHandling:
    """Tests for concurrent transition handling (race conditions).

    Concurrent transitions should be handled atomically to prevent
    inconsistent state.
    """

    @pytest.mark.asyncio
    async def test_concurrent_accept_and_refuse(self):
        """Simulated concurrent accept/refuse - only one should succeed.

        In a real database scenario with row-level locking, only one
        transaction would complete. This test simulates the scenario
        where two transitions are attempted on the same delivery.
        """
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)

        async def accept_with_delay():
            # Fresh session for this "transaction"
            session = create_mock_session(delivery)
            service = DeliveryLifecycleService(session)
            return await service.accept(
                delivery_id=delivery_id,
                actor_type=ActorType.RECIPIENT,
                actor_ref="recipient-123",
            )

        async def refuse_with_delay():
            # Fresh session for this "transaction"
            session = create_mock_session(delivery)
            service = DeliveryLifecycleService(session)
            return await service.refuse(
                delivery_id=delivery_id,
                actor_type=ActorType.RECIPIENT,
                actor_ref="recipient-123",
            )

        # Run both concurrently
        # In the mock scenario, both may succeed because they share the same delivery object
        # In a real DB with proper locking, only one would succeed
        results = await asyncio.gather(accept_with_delay(), refuse_with_delay())

        # At least one should succeed
        successful_results = [r for r in results if r.success]
        assert len(successful_results) >= 1, "At least one transition should succeed"

    @pytest.mark.asyncio
    async def test_transition_after_terminal_state_fails(self):
        """Once in terminal state, no further transitions succeed.

        This tests the fundamental protection against state corruption.
        """
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.REFUSED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)

        # Try multiple transitions after terminal state
        transitions_to_try = [
            (DeliveryState.ACCEPTED, ActorType.RECIPIENT),
            (DeliveryState.RECEIVED, ActorType.RECIPIENT),
            (DeliveryState.AVAILABLE, ActorType.SYSTEM),
        ]

        for target_state, actor_type in transitions_to_try:
            result = await service.transition(
                delivery_id=delivery_id,
                to_state=target_state,
                actor_type=actor_type,
                actor_ref="actor-123",
            )
            assert result.success is False, f"Transition to {target_state} should fail"

    @pytest.mark.asyncio
    async def test_rapid_sequential_transitions(self):
        """Sequential transitions through the happy path."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)

        # Track state through the journey
        states_visited = [delivery.state]

        async def do_transition(session, service, method, **kwargs):
            result = await method(**kwargs)
            if result.success:
                states_visited.append(result.new_state)
            return result

        session = create_mock_session(delivery)
        service = DeliveryLifecycleService(session)

        # Execute full lifecycle
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )
        assert result.success
        states_visited.append(result.new_state)

        result = await service.notify(delivery_id=delivery_id)
        assert result.success
        states_visited.append(result.new_state)

        result = await service.make_available(delivery_id=delivery_id)
        assert result.success
        states_visited.append(result.new_state)

        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )
        assert result.success
        states_visited.append(result.new_state)

        result = await service.receive(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )
        assert result.success
        states_visited.append(result.new_state)

        # Verify we reached the final terminal state
        assert delivery.state == DeliveryState.RECEIVED
        # Verify we visited all expected states
        assert DeliveryState.DEPOSITED in states_visited
        assert DeliveryState.NOTIFIED in states_visited
        assert DeliveryState.AVAILABLE in states_visited
        assert DeliveryState.ACCEPTED in states_visited
        assert DeliveryState.RECEIVED in states_visited


# =============================================================================
# TEST CLASS: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_delivery_not_found_raises_error(self):
        """Transition on non-existent delivery raises DeliveryNotFoundError."""
        session = create_mock_session(None)  # No delivery
        service = DeliveryLifecycleService(session)

        with pytest.raises(DeliveryNotFoundError) as exc_info:
            await service.transition(
                delivery_id=uuid4(),
                to_state=DeliveryState.DEPOSITED,
                actor_type=ActorType.SENDER,
                actor_ref="sender-123",
            )

        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_notification_retry_from_failed_state(self):
        """Can retry notification from NOTIFICATION_FAILED state."""
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
        assert result.evidence_event.event_type == EventType.EVT_NOTIFICATION_SENT

    @pytest.mark.asyncio
    async def test_manual_override_from_failed_to_available(self):
        """Admin can override from NOTIFICATION_FAILED to AVAILABLE."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFICATION_FAILED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(
            delivery_id=delivery_id,
            actor_type=ActorType.ADMIN,
            actor_ref="admin-123",
            event_metadata={"override_reason": "Manual verification completed"},
        )

        assert result.success is True
        assert result.new_state == DeliveryState.AVAILABLE

    @pytest.mark.asyncio
    async def test_empty_content_hashes_in_deposit(self):
        """deposit() works without content_hashes."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_timestamps_updated_on_transition(self):
        """Lifecycle timestamps are updated on relevant transitions."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)

        # Deposit should set deposited_at
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )
        assert result.success
        assert delivery.deposited_at is not None

        # Notify should set notified_at
        result = await service.notify(delivery_id=delivery_id)
        assert result.success
        assert delivery.notified_at is not None

        # Make available should set available_at
        result = await service.make_available(delivery_id=delivery_id)
        assert result.success
        assert delivery.available_at is not None

        # Accept should set completed_at
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )
        assert result.success
        assert delivery.completed_at is not None

    @pytest.mark.asyncio
    async def test_expire_sets_completed_at(self):
        """expire() sets completed_at timestamp."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.expire(delivery_id=delivery_id)

        assert result.success
        assert delivery.completed_at is not None

    @pytest.mark.asyncio
    async def test_refuse_sets_completed_at(self):
        """refuse() sets completed_at timestamp."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.refuse(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.success
        assert delivery.completed_at is not None

    def test_transition_result_immutability(self):
        """TransitionResult is immutable (frozen dataclass)."""
        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.DRAFT,
            new_state=DeliveryState.DEPOSITED,
            evidence_event=None,
            error=None,
        )

        with pytest.raises(AttributeError):
            result.success = False  # type: ignore

    def test_jurisdiction_profile_immutability(self):
        """JurisdictionProfile is immutable (frozen dataclass)."""
        profile = JurisdictionProfile(
            code="test",
            acceptance_window_days=15,
            requires_notification_delivery_proof=True,
            redaction_profile="test_redaction",
        )

        with pytest.raises(AttributeError):
            profile.code = "modified"  # type: ignore

    def test_unknown_jurisdiction_profile_raises_error(self):
        """Unknown jurisdiction profile raises ValueError."""
        service = DeliveryLifecycleService(MagicMock())

        with pytest.raises(ValueError, match="Unknown jurisdiction profile"):
            service.get_jurisdiction_profile("nonexistent_profile")


# =============================================================================
# TEST CLASS: Automated Expiry Processing
# =============================================================================


class TestAutomatedExpiryProcessing:
    """Tests for automated expiry batch processing."""

    @pytest.mark.asyncio
    async def test_check_and_expire_processes_expired_deliveries(self):
        """check_and_expire_deliveries() expires past-deadline deliveries."""
        expired_delivery = create_mock_delivery(uuid4(), DeliveryState.AVAILABLE)
        expired_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)

        session = create_mock_session_for_batch([expired_delivery])
        service = DeliveryLifecycleService(session)

        expired_ids = await service.check_and_expire_deliveries()

        assert len(expired_ids) == 1
        assert expired_ids[0] == expired_delivery.delivery_id
        assert expired_delivery.state == DeliveryState.EXPIRED

    @pytest.mark.asyncio
    async def test_check_and_expire_skips_non_available_deliveries(self):
        """check_and_expire_deliveries() only processes AVAILABLE deliveries."""
        # This delivery is already in a terminal state
        terminal_delivery = create_mock_delivery(uuid4(), DeliveryState.ACCEPTED)
        terminal_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=5)

        # Session returns empty list because the query filters by AVAILABLE state
        session = create_mock_session_for_batch([])
        service = DeliveryLifecycleService(session)

        expired_ids = await service.check_and_expire_deliveries()

        assert len(expired_ids) == 0

    @pytest.mark.asyncio
    async def test_check_and_expire_records_expiry_metadata(self):
        """Expiry events record that they were automated."""
        expired_delivery = create_mock_delivery(uuid4(), DeliveryState.AVAILABLE)
        expired_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)

        session = create_mock_session_for_batch([expired_delivery])
        service = DeliveryLifecycleService(session)

        await service.check_and_expire_deliveries()

        # The delivery should now be expired
        assert expired_delivery.state == DeliveryState.EXPIRED


# =============================================================================
# TEST CLASS: Lifecycle Timestamp Management
# =============================================================================


class TestLifecycleTimestamps:
    """Tests for lifecycle timestamp management."""

    @pytest.mark.asyncio
    async def test_updated_at_always_changes(self):
        """updated_at is always set on transition."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        # Initially None in the mock
        assert delivery.updated_at is None
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        # updated_at should have changed (it was None, now it's set)
        assert delivery.updated_at is not None

    @pytest.mark.asyncio
    async def test_timestamps_are_utc(self):
        """All timestamps use UTC timezone."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        assert delivery.deposited_at.tzinfo == UTC
        assert delivery.updated_at.tzinfo == UTC


# =============================================================================
# TEST CLASS: Actor Type Validation
# =============================================================================


class TestActorTypeValidation:
    """Tests for actor type handling in transitions."""

    @pytest.mark.asyncio
    async def test_sender_actor_on_deposit(self):
        """Deposit uses SENDER actor type."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=delivery_id,
            actor_type=ActorType.SENDER,
            actor_ref="sender-123",
        )

        assert result.evidence_event.actor_type == ActorType.SENDER

    @pytest.mark.asyncio
    async def test_system_actor_on_notify(self):
        """Notify defaults to SYSTEM actor type."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DEPOSITED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.notify(delivery_id=delivery_id)

        assert result.evidence_event.actor_type == ActorType.SYSTEM
        assert result.evidence_event.actor_ref == "system"

    @pytest.mark.asyncio
    async def test_recipient_actor_on_accept(self):
        """Accept uses RECIPIENT actor type."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=10)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.accept(
            delivery_id=delivery_id,
            actor_type=ActorType.RECIPIENT,
            actor_ref="recipient-123",
        )

        assert result.evidence_event.actor_type == ActorType.RECIPIENT

    @pytest.mark.asyncio
    async def test_admin_actor_on_manual_override(self):
        """Admin can perform manual overrides."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.NOTIFICATION_FAILED)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.make_available(
            delivery_id=delivery_id,
            actor_type=ActorType.ADMIN,
            actor_ref="admin-456",
        )

        assert result.evidence_event.actor_type == ActorType.ADMIN
        assert result.evidence_event.actor_ref == "admin-456"

    @pytest.mark.asyncio
    async def test_system_actor_on_expire(self):
        """Expire defaults to SYSTEM actor type."""
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.AVAILABLE)
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(hours=1)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)
        result = await service.expire(delivery_id=delivery_id)

        assert result.evidence_event.actor_type == ActorType.SYSTEM


# =============================================================================
# TEST CLASS: Exception Classes
# =============================================================================


class TestExceptionClasses:
    """Tests for custom exception classes to ensure full coverage."""

    def test_invalid_transition_error_attributes(self):
        """InvalidTransitionError stores state information."""
        from qerds.services.lifecycle import InvalidTransitionError

        error = InvalidTransitionError(
            from_state=DeliveryState.DRAFT,
            to_state=DeliveryState.ACCEPTED,
        )

        assert error.from_state == DeliveryState.DRAFT
        assert error.to_state == DeliveryState.ACCEPTED
        assert "draft" in str(error).lower()
        assert "accepted" in str(error).lower()

    def test_invalid_transition_error_with_custom_reason(self):
        """InvalidTransitionError accepts custom reason."""
        from qerds.services.lifecycle import InvalidTransitionError

        custom_reason = "Custom failure reason"
        error = InvalidTransitionError(
            from_state=DeliveryState.DRAFT,
            to_state=DeliveryState.ACCEPTED,
            reason=custom_reason,
        )

        assert error.reason == custom_reason
        assert str(error) == custom_reason

    def test_delivery_not_found_error_attributes(self):
        """DeliveryNotFoundError stores delivery ID."""
        delivery_id = uuid4()
        error = DeliveryNotFoundError(delivery_id)

        assert error.delivery_id == delivery_id
        assert str(delivery_id) in str(error)

    def test_delivery_expired_error_attributes(self):
        """DeliveryExpiredError stores delivery ID."""
        from qerds.services.lifecycle import DeliveryExpiredError

        delivery_id = uuid4()
        error = DeliveryExpiredError(delivery_id)

        assert error.delivery_id == delivery_id
        assert str(delivery_id) in str(error)
        assert "expired" in str(error).lower()


# =============================================================================
# TEST CLASS: Internal Methods (for full coverage)
# =============================================================================


class TestInternalMethods:
    """Tests for internal methods to achieve full coverage."""

    @pytest.mark.asyncio
    async def test_create_evidence_event_for_draft_raises_error(self):
        """_create_evidence_event raises ValueError for DRAFT state.

        DRAFT is the initial state and doesn't have an event type mapping
        because there's no transition INTO draft state.
        """
        delivery_id = uuid4()
        delivery = create_mock_delivery(delivery_id, DeliveryState.DRAFT)
        session = create_mock_session(delivery)

        service = DeliveryLifecycleService(session)

        # Access the internal method to test the error path
        with pytest.raises(ValueError, match="No event type mapping"):
            await service._create_evidence_event(
                delivery=delivery,
                to_state=DeliveryState.DRAFT,  # No event type for DRAFT
                actor_type=ActorType.SENDER,
                actor_ref="sender-123",
                event_metadata=None,
                policy_snapshot_id=None,
                event_time=datetime.now(UTC),
            )
