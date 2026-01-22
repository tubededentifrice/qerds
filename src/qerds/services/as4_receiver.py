"""AS4 message receiving service for cross-provider interoperability.

Covers: REQ-C04 (ETSI interoperability), REQ-B03, REQ-C01

This module handles inbound AS4 messages from Domibus gateway:
- Validates message format per ETSI EN 319 522-4-2
- Extracts content and metadata from AS4 payloads
- Creates local delivery records for received deliveries
- Generates EVT_AS4_RECEIVED evidence events
- Generates receipt for sender acknowledgment

Integration with Domibus:
- Domibus receives AS4 messages from external providers
- qerds-api polls Domibus for pending messages OR receives webhook callbacks
- This service processes the retrieved message payloads
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID, uuid4

from qerds.db.models.base import ActorType, DeliveryState, EventType

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AS4MessageType(Enum):
    """Types of AS4 messages per ETSI EN 319 522-4-2."""

    # Delivery submission from sender's provider
    SUBMISSION = "submission"
    # Relay message between providers
    RELAY = "relay"
    # Dispatch notification (content now available)
    DISPATCH = "dispatch"
    # Receipt/acknowledgment
    RECEIPT = "receipt"
    # Error notification
    ERROR = "error"


class AS4ValidationError(Exception):
    """Raised when AS4 message validation fails."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.code = code
        self.details = details or {}
        super().__init__(message)


class AS4ProcessingError(Exception):
    """Raised when AS4 message processing fails."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.code = code
        self.details = details or {}
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AS4MessageMetadata:
    """Metadata extracted from an AS4 message.

    Attributes:
        message_id: Unique AS4 message identifier.
        conversation_id: Conversation tracking ID (for related messages).
        from_party_id: Sender provider's party identifier.
        to_party_id: Recipient provider's party identifier.
        service: ETSI service identifier.
        action: ETSI action type.
        timestamp: Message timestamp (from AS4 header).
        ref_to_message_id: Reference to related message (for receipts/errors).
        properties: Additional message properties.
    """

    message_id: str
    conversation_id: str
    from_party_id: str
    to_party_id: str
    service: str
    action: str
    timestamp: datetime
    ref_to_message_id: str | None = None
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AS4Payload:
    """Content payload from an AS4 message.

    Attributes:
        content_id: Payload identifier within the message.
        content_type: MIME type of the payload.
        data: Raw payload bytes.
        sha256: SHA-256 digest of the payload.
        filename: Original filename if provided.
    """

    content_id: str
    content_type: str
    data: bytes
    sha256: str
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class AS4ReceiveResult:
    """Result of processing an inbound AS4 message.

    Attributes:
        success: Whether processing succeeded.
        delivery_id: UUID of the created/updated delivery.
        evidence_event_id: UUID of the EVT_AS4_RECEIVED event.
        receipt_message_id: ID of the generated receipt message (for acknowledgment).
        error_code: Error code if processing failed.
        error_message: Error description if processing failed.
    """

    success: bool
    delivery_id: UUID | None = None
    evidence_event_id: UUID | None = None
    receipt_message_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class AS4Receipt:
    """AS4 receipt for sender acknowledgment.

    Attributes:
        receipt_message_id: Unique ID for this receipt.
        ref_to_message_id: ID of the message being acknowledged.
        timestamp: Receipt generation timestamp.
        receipt_type: Type of receipt (delivery, relay, etc.).
        digest: SHA-256 digest of the original message.
    """

    receipt_message_id: str
    ref_to_message_id: str
    timestamp: datetime
    receipt_type: str
    digest: str


class AS4MessageHandler:
    """Handles inbound AS4 messages from Domibus.

    This service processes AS4 messages received via the Domibus gateway,
    validates them per ETSI EN 319 522-4-2, creates local delivery records,
    and generates evidence events.

    Example:
        handler = AS4MessageHandler(session)
        result = await handler.process_inbound_message(
            metadata=AS4MessageMetadata(...),
            payloads=[AS4Payload(...)],
        )
        if result.success:
            # Send receipt back via Domibus
            await domibus_client.send_receipt(result.receipt_message_id)
    """

    # ETSI EN 319 522-4-2 service and action identifiers
    ETSI_SERVICE_QERDS = "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088"
    ETSI_ACTION_SUBMISSION = "http://docs.oasis-open.org/ebxml-msg/as4/200902/action/submit"
    ETSI_ACTION_DELIVERY = "http://docs.oasis-open.org/ebxml-msg/as4/200902/action/deliver"

    # Supported message types
    SUPPORTED_ACTIONS: ClassVar[set[str]] = {
        "submission",
        "delivery",
        "relay",
        "dispatch",
    }

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the AS4 message handler.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session

    async def process_inbound_message(
        self,
        metadata: AS4MessageMetadata,
        payloads: list[AS4Payload],
        *,
        raw_message_digest: str | None = None,
    ) -> AS4ReceiveResult:
        """Process an inbound AS4 message from Domibus.

        This method:
        1. Validates the message metadata and payloads
        2. Extracts delivery information from the ETSI payload
        3. Creates a local delivery record if new
        4. Creates EVT_AS4_RECEIVED evidence event
        5. Generates a receipt for sender acknowledgment

        Args:
            metadata: AS4 message metadata from Domibus.
            payloads: List of content payloads in the message.
            raw_message_digest: Optional digest of the raw AS4 message.

        Returns:
            AS4ReceiveResult with processing outcome.

        Raises:
            AS4ValidationError: If message format is invalid.
            AS4ProcessingError: If processing fails.
        """
        try:
            # Step 1: Validate message metadata
            self._validate_metadata(metadata)

            # Step 2: Validate payloads
            self._validate_payloads(payloads)

            # Step 3: Parse ETSI delivery envelope from first payload
            delivery_info = self._parse_delivery_envelope(payloads)

            # Step 4: Create or retrieve local delivery record
            delivery_id = await self._create_local_delivery(
                metadata=metadata,
                delivery_info=delivery_info,
                payloads=payloads,
            )

            # Step 5: Create evidence event
            event_id = await self._create_evidence_event(
                delivery_id=delivery_id,
                metadata=metadata,
                payloads=payloads,
            )

            # Step 6: Generate receipt
            receipt = self._generate_receipt(
                metadata=metadata,
                raw_message_digest=raw_message_digest,
            )

            await self._session.commit()

            logger.info(
                "Successfully processed AS4 message",
                extra={
                    "message_id": metadata.message_id,
                    "delivery_id": str(delivery_id),
                    "event_id": str(event_id),
                    "receipt_id": receipt.receipt_message_id,
                },
            )

            return AS4ReceiveResult(
                success=True,
                delivery_id=delivery_id,
                evidence_event_id=event_id,
                receipt_message_id=receipt.receipt_message_id,
            )

        except AS4ValidationError as e:
            logger.warning(
                "AS4 message validation failed",
                extra={
                    "message_id": metadata.message_id,
                    "error_code": e.code,
                    "error": str(e),
                },
            )
            return AS4ReceiveResult(
                success=False,
                error_code=e.code,
                error_message=str(e),
            )
        except AS4ProcessingError as e:
            logger.error(
                "AS4 message processing failed",
                extra={
                    "message_id": metadata.message_id,
                    "error_code": e.code,
                    "error": str(e),
                },
            )
            return AS4ReceiveResult(
                success=False,
                error_code=e.code,
                error_message=str(e),
            )
        except Exception as e:
            logger.exception(
                "Unexpected error processing AS4 message",
                extra={"message_id": metadata.message_id},
            )
            return AS4ReceiveResult(
                success=False,
                error_code="INTERNAL_ERROR",
                error_message=f"Unexpected error: {e!s}",
            )

    def _validate_metadata(self, metadata: AS4MessageMetadata) -> None:
        """Validate AS4 message metadata.

        Args:
            metadata: Message metadata to validate.

        Raises:
            AS4ValidationError: If validation fails.
        """
        if not metadata.message_id:
            raise AS4ValidationError(
                code="MISSING_MESSAGE_ID",
                message="AS4 message ID is required",
            )

        if not metadata.from_party_id:
            raise AS4ValidationError(
                code="MISSING_FROM_PARTY",
                message="Source party ID is required",
            )

        if not metadata.to_party_id:
            raise AS4ValidationError(
                code="MISSING_TO_PARTY",
                message="Destination party ID is required",
            )

        if not metadata.conversation_id:
            raise AS4ValidationError(
                code="MISSING_CONVERSATION_ID",
                message="Conversation ID is required for message correlation",
            )

        # Validate action is supported
        action_lower = metadata.action.lower().split("/")[-1] if metadata.action else ""
        if action_lower not in self.SUPPORTED_ACTIONS:
            raise AS4ValidationError(
                code="UNSUPPORTED_ACTION",
                message=f"Unsupported AS4 action: {metadata.action}",
                details={"supported_actions": list(self.SUPPORTED_ACTIONS)},
            )

    def _validate_payloads(self, payloads: list[AS4Payload]) -> None:
        """Validate AS4 message payloads.

        Args:
            payloads: List of payloads to validate.

        Raises:
            AS4ValidationError: If validation fails.
        """
        if not payloads:
            raise AS4ValidationError(
                code="MISSING_PAYLOAD",
                message="At least one payload is required",
            )

        for payload in payloads:
            if not payload.content_id:
                raise AS4ValidationError(
                    code="MISSING_CONTENT_ID",
                    message="Payload content ID is required",
                )

            if not payload.data:
                raise AS4ValidationError(
                    code="EMPTY_PAYLOAD",
                    message=f"Payload {payload.content_id} has no data",
                )

            # Verify SHA-256 digest
            computed_hash = hashlib.sha256(payload.data).hexdigest()
            if payload.sha256 and computed_hash != payload.sha256.lower():
                raise AS4ValidationError(
                    code="PAYLOAD_INTEGRITY_FAILURE",
                    message=f"Payload {payload.content_id} hash mismatch",
                    details={
                        "expected": payload.sha256[:16] + "...",
                        "computed": computed_hash[:16] + "...",
                    },
                )

    def _parse_delivery_envelope(self, payloads: list[AS4Payload]) -> dict[str, Any]:
        """Parse ETSI delivery envelope from payloads.

        The first payload typically contains the ETSI EN 319 522 delivery
        envelope with recipient information and metadata.

        Args:
            payloads: Message payloads.

        Returns:
            Parsed delivery information dict.
        """
        # Look for XML envelope payload
        envelope_payload = None
        for payload in payloads:
            if payload.content_type in {
                "application/xml",
                "text/xml",
                "application/vnd.etsi.erds+xml",
            }:
                envelope_payload = payload
                break

        if envelope_payload:
            # Parse XML envelope (simplified - real impl would use lxml)
            try:
                return self._parse_etsi_xml(envelope_payload.data)
            except Exception as e:
                logger.warning(
                    "Failed to parse ETSI XML envelope, using defaults",
                    extra={"error": str(e)},
                )

        # Return defaults if no parseable envelope
        return {
            "recipient_email": None,
            "recipient_name": None,
            "subject": None,
            "message": None,
            "jurisdiction_profile": "eidas",
        }

    def _parse_etsi_xml(self, xml_data: bytes) -> dict[str, Any]:
        """Parse ETSI EN 319 522 XML envelope.

        This is a simplified parser. Production implementation should use
        proper XML parsing with schema validation.

        Args:
            xml_data: Raw XML bytes.

        Returns:
            Parsed delivery information.
        """
        # NOTE: This is a stub implementation. Real ETSI parsing would use
        # defusedxml with proper namespace handling and schema validation.
        # Using defusedxml to prevent XML attacks (XXE, etc.)
        import defusedxml.ElementTree as DefusedET

        try:
            root = DefusedET.fromstring(xml_data.decode("utf-8"))
        except Exception:
            return {}

        info: dict[str, Any] = {}

        # Look for common ETSI elements (namespace-agnostic for now)
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            tag_lower = tag_local.lower()

            if tag_lower == "recipientemail" and elem.text:
                info["recipient_email"] = elem.text.strip()
            elif tag_lower == "recipientname" and elem.text:
                info["recipient_name"] = elem.text.strip()
            elif tag_lower == "subject" and elem.text:
                info["subject"] = elem.text.strip()
            elif tag_lower == "message" and elem.text:
                info["message"] = elem.text.strip()
            elif tag_lower == "jurisdictionprofile" and elem.text:
                info["jurisdiction_profile"] = elem.text.strip()

        return info

    async def _create_local_delivery(
        self,
        metadata: AS4MessageMetadata,
        delivery_info: dict[str, Any],
        payloads: list[AS4Payload],
    ) -> UUID:
        """Create a local delivery record for the received AS4 message.

        Args:
            metadata: AS4 message metadata.
            delivery_info: Parsed delivery information.
            payloads: Message payloads (for content objects).

        Returns:
            UUID of the created delivery.
        """
        from qerds.db.models.base import PartyType
        from qerds.db.models.deliveries import ContentObject, Delivery

        # Get or create sender party (external provider)
        sender_party = await self._get_or_create_external_party(
            party_identifier=metadata.from_party_id,
            party_type=PartyType.LEGAL_PERSON,
            display_name=f"Provider: {metadata.from_party_id}",
        )

        # Get or create recipient party
        recipient_email = delivery_info.get("recipient_email")
        recipient_name = delivery_info.get("recipient_name")

        if recipient_email:
            recipient_party = await self._get_or_create_party_by_email(
                email=recipient_email,
                display_name=recipient_name,
            )
        else:
            # Create placeholder recipient party from AS4 to_party_id
            recipient_party = await self._get_or_create_external_party(
                party_identifier=metadata.to_party_id,
                party_type=PartyType.LEGAL_PERSON,
                display_name=f"Recipient: {metadata.to_party_id}",
            )

        # Create delivery record
        delivery = Delivery(
            sender_party_id=sender_party.party_id,
            recipient_party_id=recipient_party.party_id,
            state=DeliveryState.DEPOSITED,  # Already deposited by external provider
            jurisdiction_profile=delivery_info.get("jurisdiction_profile", "eidas"),
            subject=delivery_info.get("subject"),
            message=delivery_info.get("message"),
            deposited_at=metadata.timestamp,
            delivery_metadata={
                "as4_message_id": metadata.message_id,
                "as4_conversation_id": metadata.conversation_id,
                "as4_from_party": metadata.from_party_id,
                "as4_service": metadata.service,
                "as4_action": metadata.action,
                "external_provider": True,
            },
        )
        self._session.add(delivery)
        await self._session.flush()

        # Create content objects from payloads (excluding XML envelope)
        for payload in payloads:
            if payload.content_type not in {
                "application/xml",
                "text/xml",
                "application/vnd.etsi.erds+xml",
            }:
                content_obj = ContentObject(
                    delivery_id=delivery.delivery_id,
                    sha256=payload.sha256 or hashlib.sha256(payload.data).hexdigest(),
                    size_bytes=len(payload.data),
                    mime_type=payload.content_type,
                    original_filename=payload.filename,
                    storage_key=f"as4-inbound/{delivery.delivery_id}/{payload.content_id}",
                )
                self._session.add(content_obj)

        return delivery.delivery_id

    async def _get_or_create_external_party(
        self,
        party_identifier: str,
        party_type: Any,  # PartyType enum
        display_name: str,
    ) -> Any:  # Party model
        """Get or create a party for an external provider.

        Args:
            party_identifier: External party identifier (e.g., AS4 party ID).
            party_type: Type of party (natural/legal person).
            display_name: Human-readable name.

        Returns:
            Party model instance.
        """
        from sqlalchemy import select

        from qerds.db.models.parties import Party

        # Look up by external_id in party metadata
        query = select(Party).where(
            Party.external_id == party_identifier,
        )
        result = await self._session.execute(query)
        party = result.scalar_one_or_none()

        if party:
            return party

        # Create new party
        party = Party(
            party_type=party_type,
            display_name=display_name,
            external_id=party_identifier,
        )
        self._session.add(party)
        await self._session.flush()

        return party

    async def _get_or_create_party_by_email(
        self,
        email: str,
        display_name: str | None = None,
    ) -> Any:  # Party model
        """Get or create a party by email address.

        Args:
            email: Email address.
            display_name: Optional display name.

        Returns:
            Party model instance.
        """
        from sqlalchemy import select

        from qerds.db.models.base import PartyType
        from qerds.db.models.parties import Party

        query = select(Party).where(Party.email == email)
        result = await self._session.execute(query)
        party = result.scalar_one_or_none()

        if party:
            return party

        party = Party(
            party_type=PartyType.NATURAL_PERSON,
            display_name=display_name or email,
            email=email,
        )
        self._session.add(party)
        await self._session.flush()

        return party

    async def _create_evidence_event(
        self,
        delivery_id: UUID,
        metadata: AS4MessageMetadata,
        payloads: list[AS4Payload],
    ) -> UUID:
        """Create EVT_AS4_RECEIVED evidence event.

        Args:
            delivery_id: UUID of the delivery.
            metadata: AS4 message metadata.
            payloads: Message payloads.

        Returns:
            UUID of the created evidence event.
        """
        from qerds.db.models.evidence import EvidenceEvent

        event = EvidenceEvent(
            delivery_id=delivery_id,
            event_type=EventType.EVT_AS4_RECEIVED,
            event_time=metadata.timestamp,
            actor_type=ActorType.SYSTEM,
            actor_ref=f"as4:{metadata.from_party_id}",
            event_metadata={
                "as4_message_id": metadata.message_id,
                "as4_conversation_id": metadata.conversation_id,
                "as4_from_party": metadata.from_party_id,
                "as4_to_party": metadata.to_party_id,
                "as4_service": metadata.service,
                "as4_action": metadata.action,
                "as4_timestamp": metadata.timestamp.isoformat(),
                "payload_count": len(payloads),
                "payload_content_ids": [p.content_id for p in payloads],
                "total_payload_bytes": sum(len(p.data) for p in payloads),
            },
        )
        self._session.add(event)
        await self._session.flush()

        return event.event_id

    def _generate_receipt(
        self,
        metadata: AS4MessageMetadata,
        raw_message_digest: str | None = None,
    ) -> AS4Receipt:
        """Generate AS4 receipt for sender acknowledgment.

        The receipt confirms that the message was received and processed.
        It should be sent back to the sender's provider via Domibus.

        Args:
            metadata: Original message metadata.
            raw_message_digest: Digest of the raw AS4 message.

        Returns:
            AS4Receipt for sending back to sender.
        """
        receipt_id = f"receipt-{uuid4()}"
        now = datetime.now(UTC)

        # Use provided digest or generate from message ID
        digest = raw_message_digest or hashlib.sha256(metadata.message_id.encode()).hexdigest()

        return AS4Receipt(
            receipt_message_id=receipt_id,
            ref_to_message_id=metadata.message_id,
            timestamp=now,
            receipt_type="delivery",
            digest=digest,
        )

    async def trigger_recipient_notification(
        self,
        delivery_id: UUID,
    ) -> None:
        """Trigger recipient notification for a received delivery.

        This queues a notification job to inform the recipient that
        a new delivery is available for pickup.

        Args:
            delivery_id: UUID of the delivery to notify about.
        """
        from qerds.services.job_queue import JobQueueService

        job_service = JobQueueService(self._session)
        await job_service.enqueue_job(
            job_type="notification_send",
            payload={
                "delivery_id": str(delivery_id),
                "notification_type": "as4_delivery_received",
            },
            queue="notifications",
        )

        logger.info(
            "Queued recipient notification for AS4 delivery",
            extra={"delivery_id": str(delivery_id)},
        )
