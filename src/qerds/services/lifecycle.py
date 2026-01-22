"""Delivery lifecycle state machine service.

Covers: REQ-B01, REQ-C01, REQ-E02, REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-F06, REQ-H10

This module implements the delivery state machine with:
- Monotonic state transitions (no backwards)
- Atomic database updates
- Evidence event generation for each transition
- Jurisdiction profile support (fr_lre, eidas)
- 15-day acceptance window enforcement (REQ-F04)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from qerds.db.models.base import ActorType, DeliveryState, EventType

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.deliveries import Delivery
    from qerds.db.models.evidence import EvidenceEvent

logger = logging.getLogger(__name__)


# Minimum acceptance window per REQ-F04 (CPCE requirement)
DEFAULT_ACCEPTANCE_WINDOW_DAYS = 15


@dataclass(frozen=True, slots=True)
class TransitionResult:
    """Result of a state transition attempt.

    Attributes:
        success: Whether the transition was successful.
        previous_state: State before the transition (or current if failed).
        new_state: State after the transition (or current if failed).
        evidence_event: Evidence event created for the transition (None if failed).
        error: Error message if the transition failed.
    """

    success: bool
    previous_state: DeliveryState
    new_state: DeliveryState
    evidence_event: EvidenceEvent | None
    error: str | None


@dataclass(frozen=True, slots=True)
class JurisdictionProfile:
    """Configuration for a jurisdiction profile.

    Profiles define jurisdiction-specific behaviors for LRE/QERDS compliance.

    Attributes:
        code: Profile identifier (e.g., 'fr_lre', 'eidas').
        acceptance_window_days: Number of days for acceptance window.
        requires_notification_delivery_proof: Whether delivery proof is required.
        redaction_profile: Pre-acceptance redaction rules to apply.
        requires_recipient_consent: Whether prior consent is required (REQ-F06).
    """

    code: str
    acceptance_window_days: int
    requires_notification_delivery_proof: bool
    redaction_profile: str
    requires_recipient_consent: bool = False


# Standard jurisdiction profiles
JURISDICTION_PROFILES: dict[str, JurisdictionProfile] = {
    "eidas": JurisdictionProfile(
        code="eidas",
        acceptance_window_days=15,
        requires_notification_delivery_proof=False,
        redaction_profile="eidas_default",
        requires_recipient_consent=False,  # eIDAS does not require prior consent
    ),
    "fr_lre": JurisdictionProfile(
        code="fr_lre",
        acceptance_window_days=15,  # CPCE requires minimum 15 days
        requires_notification_delivery_proof=True,  # LRE needs delivery confirmation
        redaction_profile="fr_lre_cpce",  # French CPCE sender redaction rules
        requires_recipient_consent=True,  # CPCE REQ-F06: consumer consent required
    ),
}


class InvalidTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""

    def __init__(
        self,
        from_state: DeliveryState,
        to_state: DeliveryState,
        reason: str | None = None,
    ) -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason or f"Cannot transition from {from_state.value} to {to_state.value}"
        super().__init__(self.reason)


class DeliveryNotFoundError(Exception):
    """Raised when a delivery is not found."""

    def __init__(self, delivery_id: UUID) -> None:
        self.delivery_id = delivery_id
        super().__init__(f"Delivery {delivery_id} not found")


class DeliveryExpiredError(Exception):
    """Raised when an operation is attempted on an expired delivery."""

    def __init__(self, delivery_id: UUID) -> None:
        self.delivery_id = delivery_id
        super().__init__(f"Delivery {delivery_id} has expired")


class ConsentRequiredForDeliveryError(Exception):
    """Raised when recipient consent is required but not granted (REQ-F06)."""

    def __init__(self, recipient_party_id: UUID, jurisdiction_profile: str) -> None:
        self.recipient_party_id = recipient_party_id
        self.jurisdiction_profile = jurisdiction_profile
        super().__init__(
            f"Recipient consent required for {jurisdiction_profile} delivery "
            f"to party {recipient_party_id}"
        )


class DeliveryLifecycleService:
    """Service for managing delivery state transitions.

    Implements the QERDS delivery state machine with:
    - Valid transition enforcement (monotonic, no backwards)
    - Evidence event generation for compliance
    - Atomic database updates
    - Jurisdiction-specific behavior

    The state machine follows this flow:
        draft -> deposited -> notified -> available -> accepted/refused -> received
                              |                                             |
                              v                                             |
                       notification_failed (retry)                          |
                                                                            v
                                                                         expired

    Example:
        service = DeliveryLifecycleService(session)
        result = await service.deposit(
            delivery_id=uuid,
            actor_type=ActorType.SENDER,
            actor_ref="party-123",
        )
        if result.success:
            print(f"Deposited: {result.evidence_event.event_id}")
    """

    # Valid state transitions: from_state -> [allowed_to_states]
    # Transitions are monotonic - no backwards movement except notification retry
    VALID_TRANSITIONS: ClassVar[dict[DeliveryState, set[DeliveryState]]] = {
        DeliveryState.DRAFT: {DeliveryState.DEPOSITED},
        DeliveryState.DEPOSITED: {DeliveryState.NOTIFIED},
        DeliveryState.NOTIFIED: {
            DeliveryState.NOTIFICATION_FAILED,  # Bounce/failure
            DeliveryState.AVAILABLE,  # Content ready for pickup
        },
        DeliveryState.NOTIFICATION_FAILED: {
            DeliveryState.NOTIFIED,  # Retry notification
            DeliveryState.AVAILABLE,  # Manual override to available
        },
        DeliveryState.AVAILABLE: {
            DeliveryState.ACCEPTED,
            DeliveryState.REFUSED,
            DeliveryState.EXPIRED,
        },
        DeliveryState.ACCEPTED: {DeliveryState.RECEIVED},
        # Terminal states - no transitions out
        DeliveryState.REFUSED: set(),
        DeliveryState.RECEIVED: set(),
        DeliveryState.EXPIRED: set(),
    }

    # Map state transitions to evidence event types
    TRANSITION_EVENTS: ClassVar[dict[DeliveryState, EventType]] = {
        DeliveryState.DEPOSITED: EventType.EVT_DEPOSITED,
        DeliveryState.NOTIFIED: EventType.EVT_NOTIFICATION_SENT,
        DeliveryState.NOTIFICATION_FAILED: EventType.EVT_NOTIFICATION_FAILED,
        DeliveryState.AVAILABLE: EventType.EVT_CONTENT_AVAILABLE,
        DeliveryState.ACCEPTED: EventType.EVT_ACCEPTED,
        DeliveryState.REFUSED: EventType.EVT_REFUSED,
        DeliveryState.RECEIVED: EventType.EVT_RECEIVED,
        DeliveryState.EXPIRED: EventType.EVT_EXPIRED,
    }

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the lifecycle service.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session

    def get_jurisdiction_profile(self, profile_code: str) -> JurisdictionProfile:
        """Get jurisdiction profile by code.

        Args:
            profile_code: Profile identifier (e.g., 'fr_lre', 'eidas').

        Returns:
            JurisdictionProfile for the given code.

        Raises:
            ValueError: If profile code is not recognized.
        """
        if profile_code not in JURISDICTION_PROFILES:
            raise ValueError(
                f"Unknown jurisdiction profile: {profile_code}. "
                f"Valid profiles: {list(JURISDICTION_PROFILES.keys())}"
            )
        return JURISDICTION_PROFILES[profile_code]

    def is_valid_transition(
        self,
        from_state: DeliveryState,
        to_state: DeliveryState,
    ) -> bool:
        """Check if a state transition is valid.

        Args:
            from_state: Current state.
            to_state: Desired target state.

        Returns:
            True if the transition is allowed, False otherwise.
        """
        valid_targets = self.VALID_TRANSITIONS.get(from_state, set())
        return to_state in valid_targets

    def is_terminal_state(self, state: DeliveryState) -> bool:
        """Check if a state is terminal (no outgoing transitions).

        Args:
            state: State to check.

        Returns:
            True if the state is terminal, False otherwise.
        """
        return len(self.VALID_TRANSITIONS.get(state, set())) == 0

    async def get_delivery(self, delivery_id: UUID) -> Delivery:
        """Get a delivery by ID.

        Args:
            delivery_id: UUID of the delivery.

        Returns:
            The Delivery model instance.

        Raises:
            DeliveryNotFoundError: If the delivery does not exist.
        """
        from sqlalchemy import select

        from qerds.db.models.deliveries import Delivery

        query = select(Delivery).where(Delivery.delivery_id == delivery_id)
        result = await self._session.execute(query)
        delivery = result.scalar_one_or_none()

        if delivery is None:
            raise DeliveryNotFoundError(delivery_id)

        return delivery

    async def transition(
        self,
        delivery_id: UUID,
        to_state: DeliveryState,
        *,
        actor_type: ActorType,
        actor_ref: str,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Perform a state transition with validation and evidence recording.

        This is the core transition method. It:
        1. Validates the transition is allowed
        2. Updates the delivery state atomically
        3. Creates an evidence event for the transition
        4. Returns the result with the new state

        Args:
            delivery_id: UUID of the delivery to transition.
            to_state: Target state for the transition.
            actor_type: Type of actor performing the transition.
            actor_ref: Reference to the actor (party_id, admin_id, or 'system').
            event_metadata: Additional metadata to include in the evidence event.
            policy_snapshot_id: Optional policy snapshot ID for compliance.

        Returns:
            TransitionResult with success status and evidence event.
        """
        delivery = await self.get_delivery(delivery_id)
        from_state = delivery.state

        # Validate transition is allowed
        if not self.is_valid_transition(from_state, to_state):
            logger.warning(
                "Invalid transition attempted",
                extra={
                    "delivery_id": str(delivery_id),
                    "from_state": from_state.value,
                    "to_state": to_state.value,
                    "actor_type": actor_type.value,
                    "actor_ref": actor_ref,
                },
            )
            return TransitionResult(
                success=False,
                previous_state=from_state,
                new_state=from_state,
                evidence_event=None,
                error=f"Invalid transition from {from_state.value} to {to_state.value}",
            )

        # Check if expired (only for states that require deadline check)
        deadline_check_states = {DeliveryState.ACCEPTED, DeliveryState.REFUSED}
        deadline_passed = (
            delivery.acceptance_deadline_at and datetime.now(UTC) > delivery.acceptance_deadline_at
        )
        if to_state in deadline_check_states and deadline_passed:
            # Delivery has expired - cannot accept/refuse
            logger.info(
                "Delivery expired, rejecting accept/refuse",
                extra={
                    "delivery_id": str(delivery_id),
                    "deadline": delivery.acceptance_deadline_at.isoformat(),
                },
            )
            return TransitionResult(
                success=False,
                previous_state=from_state,
                new_state=from_state,
                evidence_event=None,
                error="Delivery acceptance deadline has passed",
            )

        # Perform the transition
        now = datetime.now(UTC)
        delivery.state = to_state
        delivery.updated_at = now

        # Set lifecycle timestamps based on transition
        self._update_lifecycle_timestamps(delivery, to_state, now)

        # Create evidence event
        evidence_event = await self._create_evidence_event(
            delivery=delivery,
            to_state=to_state,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=event_metadata,
            policy_snapshot_id=policy_snapshot_id,
            event_time=now,
        )

        await self._session.flush()

        logger.info(
            "State transition completed",
            extra={
                "delivery_id": str(delivery_id),
                "from_state": from_state.value,
                "to_state": to_state.value,
                "event_id": str(evidence_event.event_id),
            },
        )

        return TransitionResult(
            success=True,
            previous_state=from_state,
            new_state=to_state,
            evidence_event=evidence_event,
            error=None,
        )

    async def verify_recipient_consent(
        self,
        recipient_party_id: UUID,
        jurisdiction_profile: str,
    ) -> bool:
        """Verify recipient has valid consent for LRE delivery (REQ-F06).

        This method should be called before creating or depositing a delivery
        when the jurisdiction requires prior recipient consent.

        Args:
            recipient_party_id: UUID of the recipient party.
            jurisdiction_profile: Jurisdiction profile (e.g., "fr_lre", "eidas").

        Returns:
            True if consent is valid or not required.

        Raises:
            ConsentRequiredForDeliveryError: If consent is required but not granted.
        """
        profile = self.get_jurisdiction_profile(jurisdiction_profile)

        # If profile doesn't require consent, return True
        if not profile.requires_recipient_consent:
            return True

        # Import consent service and check
        from qerds.services.consent import ConsentRequiredError, ConsentService

        consent_service = ConsentService(self._session)

        try:
            await consent_service.verify_consent_for_delivery(
                recipient_party_id=recipient_party_id,
                jurisdiction_profile=jurisdiction_profile,
            )
            return True
        except ConsentRequiredError as e:
            logger.warning(
                "Delivery blocked: recipient consent not granted",
                extra={
                    "recipient_party_id": str(recipient_party_id),
                    "jurisdiction_profile": jurisdiction_profile,
                },
            )
            raise ConsentRequiredForDeliveryError(
                recipient_party_id=recipient_party_id,
                jurisdiction_profile=jurisdiction_profile,
            ) from e

    async def deposit(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType,
        actor_ref: str,
        content_hashes: list[str] | None = None,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
        verify_consent: bool = True,
    ) -> TransitionResult:
        """Deposit content and transition to DEPOSITED state.

        This corresponds to EVT_DEPOSITED (REQ-B01, REQ-F01).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically SENDER).
            actor_ref: Reference to the actor.
            content_hashes: SHA-256 hashes of deposited content objects.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.
            verify_consent: Whether to verify recipient consent (REQ-F06).

        Returns:
            TransitionResult with the evidence event.

        Raises:
            ConsentRequiredForDeliveryError: If consent is required but not granted.
        """
        # Get delivery to check jurisdiction and recipient
        delivery = await self.get_delivery(delivery_id)

        # Verify consent if required (REQ-F06)
        if verify_consent and delivery.recipient_party_id:
            await self.verify_recipient_consent(
                recipient_party_id=delivery.recipient_party_id,
                jurisdiction_profile=delivery.jurisdiction_profile,
            )

        # Merge content hashes into metadata
        metadata = dict(event_metadata) if event_metadata else {}
        if content_hashes:
            metadata["content_hashes"] = content_hashes

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.DEPOSITED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def notify(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_ref: str = "system",
        notification_channel: str | None = None,
        notification_ref: str | None = None,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Send notification and transition to NOTIFIED state.

        This corresponds to EVT_NOTIFICATION_SENT (REQ-C01, REQ-F02).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically SYSTEM).
            actor_ref: Reference to the actor.
            notification_channel: Channel used (email, sms, etc.).
            notification_ref: Reference to the notification (e.g., message ID hash).
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        # Merge notification details into metadata
        metadata = dict(event_metadata) if event_metadata else {}
        if notification_channel:
            metadata["notification_channel"] = notification_channel
        if notification_ref:
            metadata["notification_ref"] = notification_ref

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.NOTIFIED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def notification_failed(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_ref: str = "system",
        failure_reason: str | None = None,
        bounce_type: str | None = None,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Record notification failure and transition to NOTIFICATION_FAILED.

        This corresponds to EVT_NOTIFICATION_FAILED (REQ-C01).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically SYSTEM).
            actor_ref: Reference to the actor.
            failure_reason: Reason for the notification failure.
            bounce_type: Type of bounce (hard, soft, etc.).
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        metadata = dict(event_metadata) if event_metadata else {}
        if failure_reason:
            metadata["failure_reason"] = failure_reason
        if bounce_type:
            metadata["bounce_type"] = bounce_type

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.NOTIFICATION_FAILED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def make_available(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_ref: str = "system",
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Make content available and transition to AVAILABLE state.

        This corresponds to EVT_CONTENT_AVAILABLE (REQ-C01, REQ-E02).
        Also sets the acceptance deadline based on jurisdiction profile.

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor.
            actor_ref: Reference to the actor.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        # Get delivery to set acceptance deadline
        delivery = await self.get_delivery(delivery_id)

        # Get jurisdiction profile for acceptance window
        profile = self.get_jurisdiction_profile(delivery.jurisdiction_profile)

        # Calculate acceptance deadline
        now = datetime.now(UTC)
        acceptance_deadline = now + timedelta(days=profile.acceptance_window_days)

        # Set the deadline before transition
        delivery.acceptance_deadline_at = acceptance_deadline

        metadata = dict(event_metadata) if event_metadata else {}
        metadata["acceptance_deadline"] = acceptance_deadline.isoformat()
        metadata["acceptance_window_days"] = profile.acceptance_window_days

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.AVAILABLE,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def accept(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType,
        actor_ref: str,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Accept delivery and transition to ACCEPTED state.

        This corresponds to EVT_ACCEPTED (REQ-C01, REQ-F04).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically RECIPIENT).
            actor_ref: Reference to the actor.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.ACCEPTED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=event_metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def refuse(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType,
        actor_ref: str,
        refusal_reason: str | None = None,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Refuse delivery and transition to REFUSED state.

        This corresponds to EVT_REFUSED (REQ-C01, REQ-F04).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically RECIPIENT).
            actor_ref: Reference to the actor.
            refusal_reason: Optional reason for refusal.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        metadata = dict(event_metadata) if event_metadata else {}
        if refusal_reason:
            metadata["refusal_reason"] = refusal_reason

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.REFUSED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def receive(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType,
        actor_ref: str,
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Record content receipt and transition to RECEIVED state.

        This corresponds to EVT_RECEIVED (REQ-B01, REQ-C01).

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically RECIPIENT).
            actor_ref: Reference to the actor.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.RECEIVED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=event_metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def expire(
        self,
        delivery_id: UUID,
        *,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_ref: str = "system",
        event_metadata: dict[str, Any] | None = None,
        policy_snapshot_id: UUID | None = None,
    ) -> TransitionResult:
        """Expire delivery and transition to EXPIRED state.

        This corresponds to EVT_EXPIRED (REQ-C01, REQ-F04).
        Called when the 15-day acceptance window passes without action.

        Args:
            delivery_id: UUID of the delivery.
            actor_type: Type of actor (typically SYSTEM).
            actor_ref: Reference to the actor.
            event_metadata: Additional metadata for the evidence event.
            policy_snapshot_id: Optional policy snapshot ID.

        Returns:
            TransitionResult with the evidence event.
        """
        delivery = await self.get_delivery(delivery_id)

        metadata = dict(event_metadata) if event_metadata else {}
        if delivery.acceptance_deadline_at:
            metadata["acceptance_deadline"] = delivery.acceptance_deadline_at.isoformat()

        return await self.transition(
            delivery_id=delivery_id,
            to_state=DeliveryState.EXPIRED,
            actor_type=actor_type,
            actor_ref=actor_ref,
            event_metadata=metadata,
            policy_snapshot_id=policy_snapshot_id,
        )

    async def check_and_expire_deliveries(
        self,
        *,
        batch_size: int = 100,
    ) -> list[UUID]:
        """Check for expired deliveries and transition them to EXPIRED state.

        This is typically called by a background job to enforce REQ-F04.

        Args:
            batch_size: Maximum number of deliveries to process.

        Returns:
            List of delivery IDs that were expired.
        """
        from sqlalchemy import select

        from qerds.db.models.deliveries import Delivery

        now = datetime.now(UTC)

        # Find deliveries in AVAILABLE state past their deadline
        query = (
            select(Delivery)
            .where(Delivery.state == DeliveryState.AVAILABLE)
            .where(Delivery.acceptance_deadline_at < now)
            .limit(batch_size)
        )

        result = await self._session.execute(query)
        expired_deliveries = result.scalars().all()

        expired_ids: list[UUID] = []
        for delivery in expired_deliveries:
            transition_result = await self.expire(
                delivery_id=delivery.delivery_id,
                actor_type=ActorType.SYSTEM,
                actor_ref="expiry_job",
                event_metadata={"expired_by": "automated_check"},
            )
            if transition_result.success:
                expired_ids.append(delivery.delivery_id)

        if expired_ids:
            logger.info(
                "Expired deliveries",
                extra={"count": len(expired_ids), "delivery_ids": [str(d) for d in expired_ids]},
            )

        return expired_ids

    def _update_lifecycle_timestamps(
        self,
        delivery: Delivery,
        to_state: DeliveryState,
        timestamp: datetime,
    ) -> None:
        """Update lifecycle timestamps based on the target state.

        Args:
            delivery: The delivery model to update.
            to_state: The target state of the transition.
            timestamp: The timestamp to record.
        """
        if to_state == DeliveryState.DEPOSITED:
            delivery.deposited_at = timestamp
        elif to_state == DeliveryState.NOTIFIED:
            delivery.notified_at = timestamp
        elif to_state == DeliveryState.AVAILABLE:
            delivery.available_at = timestamp
        elif to_state in {
            DeliveryState.ACCEPTED,
            DeliveryState.REFUSED,
            DeliveryState.RECEIVED,
            DeliveryState.EXPIRED,
        }:
            delivery.completed_at = timestamp

    async def _create_evidence_event(
        self,
        delivery: Delivery,
        to_state: DeliveryState,
        actor_type: ActorType,
        actor_ref: str,
        event_metadata: dict[str, Any] | None,
        policy_snapshot_id: UUID | None,
        event_time: datetime,
    ) -> EvidenceEvent:
        """Create an evidence event for a state transition.

        Args:
            delivery: The delivery being transitioned.
            to_state: The target state.
            actor_type: Type of actor performing the transition.
            actor_ref: Reference to the actor.
            event_metadata: Additional metadata for the event.
            policy_snapshot_id: Optional policy snapshot ID.
            event_time: Timestamp for the event.

        Returns:
            The created EvidenceEvent.
        """
        from qerds.db.models.evidence import EvidenceEvent

        event_type = self.TRANSITION_EVENTS.get(to_state)
        if event_type is None:
            # Fallback for states without explicit event type mapping
            # This shouldn't happen for standard transitions
            raise ValueError(f"No event type mapping for state: {to_state}")

        event = EvidenceEvent(
            delivery_id=delivery.delivery_id,
            event_type=event_type,
            event_time=event_time,
            actor_type=actor_type,
            actor_ref=actor_ref,
            policy_snapshot_id=policy_snapshot_id,
            event_metadata=event_metadata,
        )

        self._session.add(event)
        return event
