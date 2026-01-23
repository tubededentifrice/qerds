"""Evidence event generation service.

Covers: REQ-B01, REQ-B02, REQ-B03, REQ-C01, REQ-E02, REQ-F03, REQ-H05, REQ-H10

This module implements the evidence event generation system per
specs/implementation/30-lifecycle-and-evidence.md:

- Evidence events are immutable records of delivery lifecycle actions
- Each event captures: event_id, delivery_id, event_type, event_time, actor,
  inputs_hashes, policy_snapshot_ref
- Events support pre-acceptance redaction profiles (REQ-F03)
- Events are linked to deliveries and can be queried for timeline reconstruction

Event Types:
- EVT_DEPOSITED: Proof of deposit (REQ-B01, REQ-F01)
- EVT_NOTIFICATION_SENT: Notification issuance (REQ-C01, REQ-F02)
- EVT_NOTIFICATION_FAILED: Notification failure (REQ-C01)
- EVT_AVAILABLE: Content available under access controls (REQ-C01, REQ-E02)
- EVT_ACCEPTED: Recipient acceptance (REQ-C01, REQ-F04)
- EVT_REFUSED: Recipient refusal (REQ-C01, REQ-F04)
- EVT_RECEIVED: Recipient receipt (REQ-B01, REQ-C01)
- EVT_EXPIRED: Non-claim/expiry (REQ-C01, REQ-F04)
- EVT_CONTENT_ACCESSED: Access audit event (REQ-E02, REQ-H10)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import ActorType, EventType

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.deliveries import Delivery
    from qerds.db.models.evidence import EvidenceEvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EventData:
    """Immutable representation of an evidence event.

    This dataclass provides a frozen view of an EvidenceEvent for external use,
    ensuring immutability after retrieval.

    Attributes:
        event_id: Unique identifier for the event.
        delivery_id: UUID of the associated delivery.
        event_type: Type of lifecycle event.
        event_time: When the event occurred (authoritative timestamp).
        actor_type: Type of actor who triggered the event.
        actor_ref: Reference to the actor (party_id, admin_id, or 'system').
        policy_snapshot_id: Policy snapshot in effect at event time.
        inputs_hashes: Hashes of relevant inputs/content for integrity binding.
        event_metadata: Additional event-specific metadata.
    """

    event_id: UUID
    delivery_id: UUID
    event_type: EventType
    event_time: datetime
    actor_type: ActorType
    actor_ref: str
    policy_snapshot_id: UUID | None
    inputs_hashes: dict[str, str]
    event_metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ActorIdentification:
    """Actor identification for evidence events (REQ-B03, REQ-C04).

    Captures the identity of the actor performing an action, with references
    to verifiable identity proofing where available.

    Per EN 319 522-4-2, party identification requires an explicit identification
    scheme URI (actor_id_type) for cross-provider interoperability.

    Attributes:
        actor_type: Type of actor (sender, recipient, system, admin, api_client).
        actor_ref: Primary reference to the actor (party_id, user_id, etc.).
        actor_id_type: Identification scheme URI per EN 319 522-4-2 (optional).

    Examples:
            - urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088 (GLN)
            - urn:oasis:names:tc:ebcore:partyid-type:unregistered (internal)
            - urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002 (SIRENE)
        identity_proofing_ref: Reference to identity proofing record (optional).
        session_ref: Reference to authentication session (optional).
        ip_address_hash: Hashed IP address for privacy-preserving audit (optional).
    """

    actor_type: ActorType
    actor_ref: str
    actor_id_type: str | None = None
    identity_proofing_ref: str | None = None
    session_ref: str | None = None
    ip_address_hash: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        """Convert to metadata dict for storage in event_metadata."""
        result: dict[str, Any] = {
            "actor_type": self.actor_type.value,
            "actor_ref": self.actor_ref,
        }
        if self.actor_id_type:
            result["actor_id_type"] = self.actor_id_type
        if self.identity_proofing_ref:
            result["identity_proofing_ref"] = self.identity_proofing_ref
        if self.session_ref:
            result["session_ref"] = self.session_ref
        if self.ip_address_hash:
            result["ip_address_hash"] = self.ip_address_hash
        return result


@dataclass
class CreateEventParams:
    """Parameters for creating an evidence event.

    Attributes:
        delivery_id: UUID of the delivery this event belongs to.
        event_type: Type of lifecycle event.
        actor: Actor identification for the event.
        inputs_hashes: Dict mapping input names to their SHA-256 hashes.
        policy_snapshot_id: Policy snapshot in effect at event time.
        event_metadata: Additional event-specific metadata.
        event_time: Override event time (defaults to now). Use for testing only.
    """

    delivery_id: UUID
    event_type: EventType
    actor: ActorIdentification
    inputs_hashes: dict[str, str] = field(default_factory=dict)
    policy_snapshot_id: UUID | None = None
    event_metadata: dict[str, Any] = field(default_factory=dict)
    event_time: datetime | None = None


class EventNotFoundError(Exception):
    """Raised when an evidence event is not found."""

    def __init__(self, event_id: UUID) -> None:
        self.event_id = event_id
        super().__init__(f"Evidence event {event_id} not found")


class DeliveryNotFoundError(Exception):
    """Raised when a delivery is not found for event creation."""

    def __init__(self, delivery_id: UUID) -> None:
        self.delivery_id = delivery_id
        super().__init__(f"Delivery {delivery_id} not found")


class EvidenceService:
    """Service for creating and retrieving evidence events.

    Evidence events are immutable records that capture legally significant
    actions in the delivery lifecycle. Each event includes:

    - Unique event_id
    - Reference to the delivery
    - Event type (from the defined catalog)
    - Authoritative timestamp
    - Actor identification with proofing references
    - Input hashes for content/metadata binding
    - Policy snapshot reference for compliance verification

    This service ensures events are created atomically and can be retrieved
    for timeline reconstruction and dispute resolution.

    Example:
        service = EvidenceService(session)
        event = await service.create_event(CreateEventParams(
            delivery_id=delivery_id,
            event_type=EventType.EVT_DEPOSITED,
            actor=ActorIdentification(
                actor_type=ActorType.SENDER,
                actor_ref=str(sender_party_id),
            ),
            inputs_hashes={"content": "abc123...", "metadata": "def456..."},
            policy_snapshot_id=policy_id,
        ))
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the evidence service.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session

    async def create_event(self, params: CreateEventParams) -> EventData:
        """Create a new evidence event.

        Creates an immutable evidence event record for the specified delivery.
        The event captures all required fields per the specification.

        Args:
            params: Event creation parameters.

        Returns:
            EventData representing the created event.

        Raises:
            DeliveryNotFoundError: If the delivery does not exist.
        """
        from qerds.db.models.evidence import EvidenceEvent

        # Verify delivery exists
        delivery = await self._get_delivery(params.delivery_id)
        if delivery is None:
            raise DeliveryNotFoundError(params.delivery_id)

        # Determine event time
        event_time = params.event_time if params.event_time else datetime.now(UTC)

        # Build event metadata, merging actor info and custom metadata
        merged_metadata = {
            **params.event_metadata,
            "actor_identification": params.actor.to_metadata(),
        }

        # Include inputs_hashes in metadata for integrity verification
        if params.inputs_hashes:
            merged_metadata["inputs_hashes"] = params.inputs_hashes

        # Create the event record
        event = EvidenceEvent(
            delivery_id=params.delivery_id,
            event_type=params.event_type,
            event_time=event_time,
            actor_type=params.actor.actor_type,
            actor_ref=params.actor.actor_ref,
            policy_snapshot_id=params.policy_snapshot_id,
            event_metadata=merged_metadata,
        )

        self._session.add(event)
        await self._session.flush()

        logger.info(
            "Evidence event created",
            extra={
                "event_id": str(event.event_id),
                "delivery_id": str(params.delivery_id),
                "event_type": params.event_type.value,
                "actor_type": params.actor.actor_type.value,
            },
        )

        return self._to_event_data(event)

    async def get_event(self, event_id: UUID) -> EventData:
        """Get a single evidence event by ID.

        Args:
            event_id: UUID of the event to retrieve.

        Returns:
            EventData for the requested event.

        Raises:
            EventNotFoundError: If the event does not exist.
        """
        from sqlalchemy import select

        from qerds.db.models.evidence import EvidenceEvent

        query = select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)
        result = await self._session.execute(query)
        event = result.scalar_one_or_none()

        if event is None:
            raise EventNotFoundError(event_id)

        return self._to_event_data(event)

    async def get_events(
        self,
        delivery_id: UUID,
        *,
        event_type: EventType | None = None,
        actor_type: ActorType | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EventData]:
        """Get all evidence events for a delivery.

        Returns events in chronological order (oldest first) for timeline
        reconstruction per REQ-H10.

        Args:
            delivery_id: UUID of the delivery.
            event_type: Filter by event type (optional).
            actor_type: Filter by actor type (optional).
            since: Only include events after this time (optional).
            until: Only include events before this time (optional).
            limit: Maximum number of events to return.
            offset: Number of events to skip.

        Returns:
            List of EventData in chronological order.
        """
        from sqlalchemy import select

        from qerds.db.models.evidence import EvidenceEvent

        query = (
            select(EvidenceEvent)
            .where(EvidenceEvent.delivery_id == delivery_id)
            .order_by(EvidenceEvent.event_time.asc())
        )

        if event_type is not None:
            query = query.where(EvidenceEvent.event_type == event_type)
        if actor_type is not None:
            query = query.where(EvidenceEvent.actor_type == actor_type)
        if since is not None:
            query = query.where(EvidenceEvent.event_time >= since)
        if until is not None:
            query = query.where(EvidenceEvent.event_time <= until)

        query = query.limit(limit).offset(offset)

        result = await self._session.execute(query)
        events: Sequence[EvidenceEvent] = result.scalars().all()

        return [self._to_event_data(e) for e in events]

    async def get_event_count(
        self,
        delivery_id: UUID,
        *,
        event_type: EventType | None = None,
    ) -> int:
        """Count evidence events for a delivery.

        Args:
            delivery_id: UUID of the delivery.
            event_type: Filter by event type (optional).

        Returns:
            Number of matching events.
        """
        from sqlalchemy import func, select

        from qerds.db.models.evidence import EvidenceEvent

        query = (
            select(func.count())
            .select_from(EvidenceEvent)
            .where(EvidenceEvent.delivery_id == delivery_id)
        )

        if event_type is not None:
            query = query.where(EvidenceEvent.event_type == event_type)

        result = await self._session.execute(query)
        return result.scalar_one()

    async def get_timeline(self, delivery_id: UUID) -> list[EventData]:
        """Get complete event timeline for a delivery.

        Returns all events in chronological order for dispute resolution
        and timeline reconstruction (REQ-H10).

        Args:
            delivery_id: UUID of the delivery.

        Returns:
            Complete list of EventData in chronological order.
        """
        # Use a high limit to get all events; production should paginate
        return await self.get_events(delivery_id, limit=10000)

    async def record_content_access(
        self,
        delivery_id: UUID,
        *,
        actor: ActorIdentification,
        content_object_ids: list[UUID],
        access_type: str = "view",
        policy_snapshot_id: UUID | None = None,
        event_metadata: dict[str, Any] | None = None,
    ) -> EventData:
        """Record a content access event (REQ-E02, REQ-H10).

        This is a convenience method for recording EVT_CONTENT_ACCESSED events,
        which are required for audit trails of recipient content access.

        Args:
            delivery_id: UUID of the delivery.
            actor: Actor performing the access.
            content_object_ids: IDs of content objects accessed.
            access_type: Type of access (view, download, etc.).
            policy_snapshot_id: Policy snapshot in effect.
            event_metadata: Additional metadata.

        Returns:
            EventData for the created access event.
        """
        metadata = dict(event_metadata) if event_metadata else {}
        metadata["content_object_ids"] = [str(cid) for cid in content_object_ids]
        metadata["access_type"] = access_type

        return await self.create_event(
            CreateEventParams(
                delivery_id=delivery_id,
                event_type=EventType.EVT_CONTENT_ACCESSED,
                actor=actor,
                policy_snapshot_id=policy_snapshot_id,
                event_metadata=metadata,
            )
        )

    async def _get_delivery(self, delivery_id: UUID) -> Delivery | None:
        """Get delivery by ID for validation.

        Args:
            delivery_id: UUID of the delivery.

        Returns:
            Delivery model or None if not found.
        """
        from sqlalchemy import select

        from qerds.db.models.deliveries import Delivery

        query = select(Delivery).where(Delivery.delivery_id == delivery_id)
        result = await self._session.execute(query)
        return result.scalar_one_or_none()

    def _to_event_data(self, event: EvidenceEvent) -> EventData:
        """Convert EvidenceEvent model to EventData dataclass.

        Extracts inputs_hashes from event_metadata if present.

        Args:
            event: The EvidenceEvent model instance.

        Returns:
            Frozen EventData representation.
        """
        metadata = dict(event.event_metadata) if event.event_metadata else {}

        # Extract inputs_hashes from metadata (stored there for DB simplicity)
        inputs_hashes = metadata.pop("inputs_hashes", {})
        if not isinstance(inputs_hashes, dict):
            inputs_hashes = {}

        return EventData(
            event_id=event.event_id,
            delivery_id=event.delivery_id,
            event_type=event.event_type,
            event_time=event.event_time,
            actor_type=event.actor_type,
            actor_ref=event.actor_ref,
            policy_snapshot_id=event.policy_snapshot_id,
            inputs_hashes=inputs_hashes,
            event_metadata=metadata,
        )


def compute_content_hash(content: bytes) -> str:
    """Compute SHA-256 hash of content for integrity binding (REQ-B02).

    This is a utility function for computing hashes that should be included
    in the inputs_hashes field of evidence events.

    Args:
        content: Raw bytes to hash.

    Returns:
        Hex-encoded SHA-256 hash (64 characters).
    """
    return hashlib.sha256(content).hexdigest()


def compute_metadata_hash(metadata: dict[str, Any]) -> str:
    """Compute SHA-256 hash of metadata for integrity binding (REQ-B02).

    Uses canonical JSON serialization for deterministic hashing.

    Args:
        metadata: Dictionary to hash.

    Returns:
        Hex-encoded SHA-256 hash (64 characters).
    """
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Pre-acceptance redaction profile support (REQ-F03)
# These profiles determine which fields are visible before recipient accepts

REDACTION_PROFILES = {
    "eidas_default": {
        "hide_sender_identity": False,
        "hide_sender_details": False,
        "hide_subject": False,
        "hide_content_metadata": False,
    },
    "fr_lre_cpce": {
        # French LRE/CPCE requires hiding sender identity before acceptance
        "hide_sender_identity": True,
        "hide_sender_details": True,
        "hide_subject": False,  # Subject can be shown
        "hide_content_metadata": True,  # Hide filenames etc.
    },
}


def get_redaction_profile(profile_code: str) -> dict[str, bool]:
    """Get redaction profile configuration.

    Args:
        profile_code: Profile identifier (e.g., 'fr_lre_cpce', 'eidas_default').

    Returns:
        Dict of redaction flags.

    Raises:
        ValueError: If profile code is not recognized.
    """
    if profile_code not in REDACTION_PROFILES:
        raise ValueError(
            f"Unknown redaction profile: {profile_code}. "
            f"Valid profiles: {list(REDACTION_PROFILES.keys())}"
        )
    return REDACTION_PROFILES[profile_code]


def apply_redaction(
    data: dict[str, Any],
    profile_code: str,
    *,
    is_accepted: bool = False,
) -> dict[str, Any]:
    """Apply pre-acceptance redaction to delivery/event data (REQ-F03).

    If the delivery has been accepted, no redaction is applied (full view).
    Otherwise, the redaction profile determines which fields are hidden.

    Args:
        data: Original data dictionary.
        profile_code: Redaction profile to apply.
        is_accepted: Whether the delivery has been accepted.

    Returns:
        Redacted copy of the data (original is not modified).
    """
    # Post-acceptance: full disclosure
    if is_accepted:
        return dict(data)

    profile = get_redaction_profile(profile_code)
    result = dict(data)

    if profile.get("hide_sender_identity"):
        # Hide sender-identifying fields
        for key in ["sender_name", "sender_email", "sender_party_id"]:
            if key in result:
                result[key] = "[REDACTED]"

    if profile.get("hide_sender_details"):
        # Hide additional sender details
        for key in ["sender_address", "sender_organization", "sender_phone"]:
            if key in result:
                result[key] = "[REDACTED]"

    if profile.get("hide_subject") and "subject" in result:
        result["subject"] = "[REDACTED]"

    if profile.get("hide_content_metadata"):
        # Hide content metadata like filenames
        for key in ["original_filename", "content_description"]:
            if key in result:
                result[key] = "[REDACTED]"

    return result
