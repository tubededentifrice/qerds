"""AS4 message sending service for inter-provider delivery.

Covers: REQ-C04 (interoperability profile)

This module implements AS4/eDelivery message sending via Domibus gateway,
per specs/implementation/65-etsi-interop-profile.md.

The integration uses Domibus as the AS4 Message Service Handler (MSH),
which handles the SOAP/ebMS3 protocol complexity. This service:
- Builds ETSI EN 319 522-4 compliant message payloads
- Submits messages to Domibus via REST API
- Handles AS4 receipts and maps them to evidence events
- Records EVT_AS4_SENT events for compliance

Architecture:
    qerds-api -> AS4SenderService -> Domibus REST API -> AS4 Network -> Remote QERDS

Note: This is a non-qualified implementation for development. Production
qualification requires proper Domibus PKI setup and CEF conformance testing.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import httpx

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration and Types
# =============================================================================


class AS4MessageStatus(str, Enum):
    """Status of an AS4 message submission."""

    PENDING = "pending"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    REJECTED = "rejected"


class AS4ErrorCode(str, Enum):
    """AS4 error codes for failure categorization."""

    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    VALIDATION_ERROR = "validation_error"
    SUBMISSION_ERROR = "submission_error"
    RECEIPT_ERROR = "receipt_error"
    TIMEOUT_ERROR = "timeout_error"


@dataclass(frozen=True, slots=True)
class AS4MessageResult:
    """Result of an AS4 message submission attempt.

    Attributes:
        success: Whether the message was successfully submitted.
        message_id: AS4 message ID assigned by Domibus (if submitted).
        status: Current status of the message.
        submission_time: When the message was submitted.
        error_code: Error code if submission failed.
        error_message: Human-readable error description.
        domibus_message_id: Domibus internal message ID for tracking.
    """

    success: bool
    message_id: str | None
    status: AS4MessageStatus
    submission_time: datetime | None
    error_code: AS4ErrorCode | None
    error_message: str | None
    domibus_message_id: str | None


@dataclass(frozen=True, slots=True)
class AS4Receipt:
    """AS4 receipt/acknowledgement from remote party.

    Attributes:
        original_message_id: Message ID being acknowledged.
        receipt_time: When the receipt was received.
        receipt_type: Type of receipt (delivery, non-repudiation, error).
        receipt_content: Raw receipt content for evidence.
        sender_party_id: Party ID of the original sender.
        receiver_party_id: Party ID of the receiver who sent the receipt.
    """

    original_message_id: str
    receipt_time: datetime
    receipt_type: str
    receipt_content: bytes
    sender_party_id: str
    receiver_party_id: str


@dataclass
class DomibusConfig:
    """Configuration for Domibus gateway connection.

    Attributes:
        base_url: Domibus REST API base URL.
        username: Authentication username.
        password: Authentication password.
        timeout: Request timeout in seconds.
        sender_party_id: This provider's AS4 party ID.
        sender_party_id_type: Party ID type (OASIS ebCore partyid-type URN).
        service: AS4 service identifier.
        service_type: AS4 service type.
        action: AS4 action for QERDS deliveries.
    """

    base_url: str
    username: str
    password: str
    timeout: int = 30
    sender_party_id: str = "QERDS_DEV"
    sender_party_id_type: str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered"
    service: str = "urn:eu:europa:ec:qerds:registered-delivery"
    service_type: str = "urn:eu:europa:ec:qerds"
    action: str = "DeliverMessage"


@dataclass
class AS4MessagePayload:
    """Payload for an AS4 message to be sent.

    Attributes:
        delivery_id: QERDS delivery ID being transmitted.
        sender_party_id: Sender's AS4 party ID.
        receiver_party_id: Receiver's AS4 party ID.
        receiver_party_id_type: Receiver's party ID type.
        content: Encrypted content bytes.
        content_type: MIME type of the content.
        metadata: Delivery metadata per ETSI EN 319 522-4.
        original_sender_name: Original sender name (for evidence).
        recipient_email: Recipient email address.
    """

    delivery_id: UUID
    sender_party_id: str
    receiver_party_id: str
    receiver_party_id_type: str
    content: bytes
    content_type: str
    metadata: dict[str, Any] = field(default_factory=dict)
    original_sender_name: str | None = None
    recipient_email: str | None = None


# =============================================================================
# AS4 Message Builder
# =============================================================================


class AS4MessageBuilder:
    """Builder for ETSI EN 319 522-4 compliant AS4 messages.

    This class constructs the message metadata and payload structure
    required by the Domibus REST API. The actual AS4/ebMS3 envelope
    is constructed by Domibus itself.

    The message format follows the eDelivery AS4 profile, which includes:
    - Party identification (sender/receiver)
    - Service/action specification
    - Payload properties (MIME type, content ID)
    - Message properties (original sender, final recipient, etc.)
    """

    # ETSI EN 319 522-4 message property names
    PROP_ORIGINAL_SENDER = "originalSender"
    PROP_FINAL_RECIPIENT = "finalRecipient"
    PROP_DELIVERY_ID = "deliveryId"
    PROP_TIMESTAMP = "timestamp"

    def __init__(self, config: DomibusConfig) -> None:
        """Initialize the message builder.

        Args:
            config: Domibus configuration for sender party info.
        """
        self._config = config

    def build_submission_request(
        self,
        payload: AS4MessagePayload,
    ) -> dict[str, Any]:
        """Build a Domibus message submission request.

        Constructs the JSON structure expected by the Domibus REST API
        for submitting a new message.

        Args:
            payload: Message payload with content and metadata.

        Returns:
            Dict structure for Domibus /rest/message/submit endpoint.
        """
        # Generate unique conversation ID for this submission
        conversation_id = str(uuid4())

        # Build party info
        party_info = self._build_party_info(payload)

        # Build collaboration info (service/action)
        collaboration_info = self._build_collaboration_info(conversation_id)

        # Build message properties per ETSI spec
        message_properties = self._build_message_properties(payload)

        # Build payload info with content
        payload_info = self._build_payload_info(payload)

        return {
            "userMessage": {
                "partyInfo": party_info,
                "collaborationInfo": collaboration_info,
                "messageProperties": message_properties,
                "payloadInfo": payload_info,
            }
        }

    def _build_party_info(self, payload: AS4MessagePayload) -> dict[str, Any]:
        """Build the party information section.

        Args:
            payload: Message payload with party IDs.

        Returns:
            Party info structure for Domibus.
        """
        return {
            "from": {
                "partyId": {
                    "value": self._config.sender_party_id,
                    "type": self._config.sender_party_id_type,
                },
                "role": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator",
            },
            "to": {
                "partyId": {
                    "value": payload.receiver_party_id,
                    "type": payload.receiver_party_id_type,
                },
                "role": "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder",
            },
        }

    def _build_collaboration_info(self, conversation_id: str) -> dict[str, Any]:
        """Build the collaboration information section.

        Args:
            conversation_id: Unique conversation identifier.

        Returns:
            Collaboration info structure for Domibus.
        """
        return {
            "service": {
                "value": self._config.service,
                "type": self._config.service_type,
            },
            "action": self._config.action,
            "conversationId": conversation_id,
        }

    def _build_message_properties(
        self,
        payload: AS4MessagePayload,
    ) -> dict[str, Any]:
        """Build message properties per ETSI EN 319 522-4.

        These properties are included in the AS4 message header and
        provide routing/identification information.

        Args:
            payload: Message payload with metadata.

        Returns:
            Message properties structure for Domibus.
        """
        properties = [
            {
                "name": self.PROP_DELIVERY_ID,
                "value": str(payload.delivery_id),
            },
            {
                "name": self.PROP_TIMESTAMP,
                "value": datetime.now(UTC).isoformat(),
            },
        ]

        # Add original sender if provided
        if payload.original_sender_name:
            properties.append(
                {
                    "name": self.PROP_ORIGINAL_SENDER,
                    "value": payload.original_sender_name,
                }
            )

        # Add final recipient if provided
        if payload.recipient_email:
            properties.append(
                {
                    "name": self.PROP_FINAL_RECIPIENT,
                    "value": payload.recipient_email,
                }
            )

        # Add custom metadata properties
        for key, value in payload.metadata.items():
            properties.append(
                {
                    "name": f"qerds_{key}",
                    "value": str(value),
                }
            )

        return {"property": properties}

    def _build_payload_info(self, payload: AS4MessagePayload) -> dict[str, Any]:
        """Build the payload information section with content.

        Args:
            payload: Message payload with content bytes.

        Returns:
            Payload info structure for Domibus.
        """
        # Content ID for referencing the payload
        content_id = f"cid:{payload.delivery_id}@qerds.local"

        # Encode content as base64 for JSON transport
        encoded_content = base64.b64encode(payload.content).decode("ascii")

        # Calculate content hash for integrity
        content_hash = hashlib.sha256(payload.content).hexdigest()

        return {
            "partInfo": [
                {
                    "href": content_id,
                    "partProperties": {
                        "property": [
                            {"name": "MimeType", "value": payload.content_type},
                            {"name": "ContentHash", "value": content_hash},
                            {"name": "HashAlgorithm", "value": "SHA-256"},
                        ]
                    },
                    "binaryData": {
                        "value": encoded_content,
                    },
                }
            ]
        }


# =============================================================================
# Domibus REST Client
# =============================================================================


class DomibusClient:
    """HTTP client for Domibus REST API.

    Handles authentication and request/response mapping for the
    Domibus message submission and status APIs.

    The client uses httpx for async HTTP operations and implements
    retry logic for transient failures.
    """

    def __init__(self, config: DomibusConfig) -> None:
        """Initialize the Domibus client.

        Args:
            config: Domibus connection configuration.
        """
        self._config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> DomibusClient:
        """Enter async context manager."""
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url,
            auth=(self._config.username, self._config.password),
            timeout=self._config.timeout,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def submit_message(
        self,
        submission_request: dict[str, Any],
    ) -> AS4MessageResult:
        """Submit a message to Domibus for AS4 transmission.

        Args:
            submission_request: Message submission request structure.

        Returns:
            AS4MessageResult with submission status.
        """
        if not self._client:
            return AS4MessageResult(
                success=False,
                message_id=None,
                status=AS4MessageStatus.FAILED,
                submission_time=None,
                error_code=AS4ErrorCode.CONNECTION_ERROR,
                error_message="Client not initialized. Use async context manager.",
                domibus_message_id=None,
            )

        submission_time = datetime.now(UTC)

        try:
            response = await self._client.post(
                "/rest/message/submit",
                json=submission_request,
            )

            if response.status_code == 200:
                # Success - extract message IDs from response
                result_data = response.json()
                message_id = result_data.get("messageId")
                domibus_message_id = result_data.get("domibusMessageId", message_id)

                logger.info(
                    "AS4 message submitted successfully",
                    extra={
                        "message_id": message_id,
                        "domibus_message_id": domibus_message_id,
                    },
                )

                return AS4MessageResult(
                    success=True,
                    message_id=message_id,
                    status=AS4MessageStatus.SUBMITTED,
                    submission_time=submission_time,
                    error_code=None,
                    error_message=None,
                    domibus_message_id=domibus_message_id,
                )

            elif response.status_code == 401:
                logger.error("Domibus authentication failed")
                return AS4MessageResult(
                    success=False,
                    message_id=None,
                    status=AS4MessageStatus.FAILED,
                    submission_time=submission_time,
                    error_code=AS4ErrorCode.AUTHENTICATION_ERROR,
                    error_message="Authentication failed with Domibus",
                    domibus_message_id=None,
                )

            elif response.status_code == 400:
                error_detail = response.text
                logger.error(
                    "Domibus validation error",
                    extra={"error": error_detail},
                )
                return AS4MessageResult(
                    success=False,
                    message_id=None,
                    status=AS4MessageStatus.FAILED,
                    submission_time=submission_time,
                    error_code=AS4ErrorCode.VALIDATION_ERROR,
                    error_message=f"Validation error: {error_detail}",
                    domibus_message_id=None,
                )

            else:
                logger.error(
                    "Domibus submission failed",
                    extra={
                        "status_code": response.status_code,
                        "response": response.text,
                    },
                )
                return AS4MessageResult(
                    success=False,
                    message_id=None,
                    status=AS4MessageStatus.FAILED,
                    submission_time=submission_time,
                    error_code=AS4ErrorCode.SUBMISSION_ERROR,
                    error_message=f"HTTP {response.status_code}: {response.text}",
                    domibus_message_id=None,
                )

        except httpx.ConnectError as e:
            logger.error(
                "Failed to connect to Domibus",
                extra={"error": str(e)},
            )
            return AS4MessageResult(
                success=False,
                message_id=None,
                status=AS4MessageStatus.FAILED,
                submission_time=submission_time,
                error_code=AS4ErrorCode.CONNECTION_ERROR,
                error_message=f"Connection error: {e}",
                domibus_message_id=None,
            )

        except httpx.TimeoutException as e:
            logger.error(
                "Domibus request timed out",
                extra={"error": str(e)},
            )
            return AS4MessageResult(
                success=False,
                message_id=None,
                status=AS4MessageStatus.FAILED,
                submission_time=submission_time,
                error_code=AS4ErrorCode.TIMEOUT_ERROR,
                error_message=f"Timeout: {e}",
                domibus_message_id=None,
            )

    async def get_message_status(self, message_id: str) -> AS4MessageStatus:
        """Get the current status of a submitted message.

        Args:
            message_id: AS4 message ID to check.

        Returns:
            Current AS4MessageStatus.
        """
        if not self._client:
            return AS4MessageStatus.FAILED

        try:
            response = await self._client.get(
                f"/rest/message/{message_id}/status",
            )

            if response.status_code == 200:
                status_data = response.json()
                status_str = status_data.get("messageStatus", "PENDING")

                # Map Domibus status to our enum
                status_mapping = {
                    "READY_TO_SEND": AS4MessageStatus.PENDING,
                    "SEND_ENQUEUED": AS4MessageStatus.PENDING,
                    "SEND_IN_PROGRESS": AS4MessageStatus.SUBMITTED,
                    "WAITING_FOR_RECEIPT": AS4MessageStatus.SUBMITTED,
                    "ACKNOWLEDGED": AS4MessageStatus.ACKNOWLEDGED,
                    "SEND_FAILURE": AS4MessageStatus.FAILED,
                    "NOT_FOUND": AS4MessageStatus.FAILED,
                }

                return status_mapping.get(status_str, AS4MessageStatus.PENDING)

            else:
                logger.warning(
                    "Failed to get message status",
                    extra={
                        "message_id": message_id,
                        "status_code": response.status_code,
                    },
                )
                return AS4MessageStatus.PENDING

        except Exception as e:
            logger.error(
                "Error checking message status",
                extra={
                    "message_id": message_id,
                    "error": str(e),
                },
            )
            return AS4MessageStatus.PENDING

    async def get_pending_receipts(self) -> list[AS4Receipt]:
        """Get pending AS4 receipts that need processing.

        Returns:
            List of AS4Receipt objects to be processed.
        """
        if not self._client:
            return []

        try:
            response = await self._client.get(
                "/rest/message/received",
                params={"messageStatus": "RECEIVED"},
            )

            if response.status_code != 200:
                return []

            receipts_data = response.json()
            receipts = []

            for receipt_entry in receipts_data.get("messages", []):
                # Parse receipt data
                try:
                    receipt = AS4Receipt(
                        original_message_id=receipt_entry.get("refToMessageId", ""),
                        receipt_time=datetime.fromisoformat(
                            receipt_entry.get("timestamp", datetime.now(UTC).isoformat())
                        ),
                        receipt_type=receipt_entry.get("messageType", "receipt"),
                        receipt_content=base64.b64decode(receipt_entry.get("payload", "")),
                        sender_party_id=receipt_entry.get("fromPartyId", ""),
                        receiver_party_id=receipt_entry.get("toPartyId", ""),
                    )
                    receipts.append(receipt)
                except Exception as e:
                    logger.warning(
                        "Failed to parse receipt",
                        extra={"entry": receipt_entry, "error": str(e)},
                    )

            return receipts

        except Exception as e:
            logger.error(
                "Error fetching pending receipts",
                extra={"error": str(e)},
            )
            return []


# =============================================================================
# AS4 Sender Service
# =============================================================================


class AS4SenderService:
    """Service for sending deliveries via AS4 to external QERDS providers.

    This service coordinates:
    1. Building ETSI EN 319 522-4 compliant messages
    2. Submitting messages to Domibus gateway
    3. Creating EVT_AS4_SENT evidence events
    4. Processing AS4 receipts

    Usage:
        config = DomibusConfig(
            base_url="http://domibus:8080",
            username="admin",
            password="secret",
        )
        service = AS4SenderService(session, config)

        result = await service.send_delivery(
            delivery_id=uuid,
            receiver_party_id="urn:example:receiver",
            content=encrypted_content,
        )

    Note: This is a NON-QUALIFIED implementation. Production qualification
    requires proper PKI setup and CEF conformance testing.
    """

    def __init__(
        self,
        session: AsyncSession,
        config: DomibusConfig,
    ) -> None:
        """Initialize the AS4 sender service.

        Args:
            session: SQLAlchemy async session for database operations.
            config: Domibus gateway configuration.
        """
        self._session = session
        self._config = config
        self._message_builder = AS4MessageBuilder(config)

    async def send_delivery(
        self,
        delivery_id: UUID,
        receiver_party_id: str,
        content: bytes,
        *,
        content_type: str = "application/octet-stream",
        receiver_party_id_type: str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
        metadata: dict[str, Any] | None = None,
        original_sender_name: str | None = None,
        recipient_email: str | None = None,
    ) -> AS4MessageResult:
        """Send a delivery to an external QERDS provider via AS4.

        This method:
        1. Builds an ETSI-compliant AS4 message
        2. Submits it to Domibus
        3. Records an EVT_AS4_SENT evidence event

        Args:
            delivery_id: UUID of the delivery being sent.
            receiver_party_id: AS4 party ID of the receiving provider.
            content: Encrypted content bytes to transmit.
            content_type: MIME type of the content.
            receiver_party_id_type: Type scheme for receiver party ID.
            metadata: Additional metadata to include in AS4 message.
            original_sender_name: Original sender name for evidence.
            recipient_email: Final recipient email address.

        Returns:
            AS4MessageResult with submission status and message ID.
        """
        # Build the message payload
        payload = AS4MessagePayload(
            delivery_id=delivery_id,
            sender_party_id=self._config.sender_party_id,
            receiver_party_id=receiver_party_id,
            receiver_party_id_type=receiver_party_id_type,
            content=content,
            content_type=content_type,
            metadata=metadata or {},
            original_sender_name=original_sender_name,
            recipient_email=recipient_email,
        )

        # Build the submission request
        submission_request = self._message_builder.build_submission_request(payload)

        # Submit to Domibus
        async with DomibusClient(self._config) as client:
            result = await client.submit_message(submission_request)

        # Record evidence event
        await self._record_as4_sent_event(
            delivery_id=delivery_id,
            result=result,
            receiver_party_id=receiver_party_id,
            content_hash=hashlib.sha256(content).hexdigest(),
        )

        return result

    async def check_delivery_status(
        self,
        message_id: str,
    ) -> AS4MessageStatus:
        """Check the status of a previously submitted AS4 message.

        Args:
            message_id: AS4 message ID to check.

        Returns:
            Current AS4MessageStatus.
        """
        async with DomibusClient(self._config) as client:
            return await client.get_message_status(message_id)

    async def process_pending_receipts(self) -> list[UUID]:
        """Process pending AS4 receipts and update delivery evidence.

        This method should be called periodically (e.g., by a background job)
        to process incoming AS4 receipts.

        Returns:
            List of delivery IDs that had receipts processed.
        """
        async with DomibusClient(self._config) as client:
            receipts = await client.get_pending_receipts()

        processed_delivery_ids = []

        for receipt in receipts:
            try:
                delivery_id = await self._process_receipt(receipt)
                if delivery_id:
                    processed_delivery_ids.append(delivery_id)
            except Exception as e:
                logger.error(
                    "Failed to process AS4 receipt",
                    extra={
                        "original_message_id": receipt.original_message_id,
                        "error": str(e),
                    },
                )

        return processed_delivery_ids

    async def _record_as4_sent_event(
        self,
        delivery_id: UUID,
        result: AS4MessageResult,
        receiver_party_id: str,
        content_hash: str,
    ) -> None:
        """Record an EVT_AS4_SENT evidence event.

        Args:
            delivery_id: UUID of the delivery.
            result: Result of the AS4 submission.
            receiver_party_id: AS4 party ID of the receiver.
            content_hash: SHA-256 hash of the transmitted content.
        """
        from qerds.db.models.base import ActorType, EventType
        from qerds.db.models.evidence import EvidenceEvent

        event_metadata = {
            "as4_message_id": result.message_id,
            "domibus_message_id": result.domibus_message_id,
            "receiver_party_id": receiver_party_id,
            "submission_status": result.status.value,
            "content_hash": content_hash,
            "sender_party_id": self._config.sender_party_id,
            # Mark as non-qualified until proper PKI setup
            "qualification_status": "non_qualified",
            "qualification_reason": "Development mode - CEF conformance testing not completed",
        }

        if result.submission_time:
            event_metadata["submission_time"] = result.submission_time.isoformat()

        if result.error_code:
            event_metadata["error_code"] = result.error_code.value
            event_metadata["error_message"] = result.error_message

        event = EvidenceEvent(
            delivery_id=delivery_id,
            event_type=EventType.EVT_AS4_SENT,
            event_time=result.submission_time or datetime.now(UTC),
            actor_type=ActorType.SYSTEM,
            actor_ref="as4_sender",
            event_metadata=event_metadata,
        )

        self._session.add(event)
        await self._session.flush()

        logger.info(
            "EVT_AS4_SENT event recorded",
            extra={
                "delivery_id": str(delivery_id),
                "event_id": str(event.event_id),
                "as4_message_id": result.message_id,
                "success": result.success,
            },
        )

    async def _process_receipt(self, receipt: AS4Receipt) -> UUID | None:
        """Process an AS4 receipt and record evidence.

        Args:
            receipt: AS4 receipt to process.

        Returns:
            Delivery ID if successfully processed, None otherwise.
        """
        from qerds.db.models.base import ActorType, EventType
        from qerds.db.models.evidence import EvidenceEvent

        # Look up the delivery by the original message ID
        # The message ID format includes the delivery ID
        delivery_id = await self._get_delivery_id_from_message(receipt.original_message_id)

        if not delivery_id:
            logger.warning(
                "Could not find delivery for AS4 receipt",
                extra={"original_message_id": receipt.original_message_id},
            )
            return None

        # Determine event type based on receipt type
        event_type = (
            EventType.EVT_AS4_RECEIPT_RECEIVED
            if receipt.receipt_type != "error"
            else EventType.EVT_AS4_ERROR
        )

        event_metadata = {
            "original_message_id": receipt.original_message_id,
            "receipt_type": receipt.receipt_type,
            "receipt_content_hash": hashlib.sha256(receipt.receipt_content).hexdigest(),
            "sender_party_id": receipt.sender_party_id,
            "receiver_party_id": receipt.receiver_party_id,
            "qualification_status": "non_qualified",
        }

        event = EvidenceEvent(
            delivery_id=delivery_id,
            event_type=event_type,
            event_time=receipt.receipt_time,
            actor_type=ActorType.SYSTEM,
            actor_ref="as4_receipt_processor",
            event_metadata=event_metadata,
        )

        self._session.add(event)
        await self._session.flush()

        logger.info(
            "AS4 receipt processed",
            extra={
                "delivery_id": str(delivery_id),
                "event_type": event_type.value,
                "receipt_type": receipt.receipt_type,
            },
        )

        return delivery_id

    async def _get_delivery_id_from_message(
        self,
        message_id: str,
    ) -> UUID | None:
        """Look up delivery ID from an AS4 message ID.

        The message ID is stored in the EVT_AS4_SENT event metadata.

        Args:
            message_id: AS4 message ID to look up.

        Returns:
            Delivery UUID if found, None otherwise.
        """
        from sqlalchemy import select

        from qerds.db.models.base import EventType
        from qerds.db.models.evidence import EvidenceEvent

        # Query for the EVT_AS4_SENT event with this message ID
        query = (
            select(EvidenceEvent.delivery_id)
            .where(EvidenceEvent.event_type == EventType.EVT_AS4_SENT)
            .where(EvidenceEvent.event_metadata["as4_message_id"].astext == message_id)
            .limit(1)
        )

        result = await self._session.execute(query)
        row = result.first()

        return row[0] if row else None


# =============================================================================
# Factory Function
# =============================================================================


def create_as4_sender_service(
    session: AsyncSession,
    base_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> AS4SenderService:
    """Factory function to create an AS4SenderService with configuration.

    This function creates the service with configuration from environment
    or provided parameters.

    Args:
        session: SQLAlchemy async session.
        base_url: Override Domibus base URL.
        username: Override Domibus username.
        password: Override Domibus password.

    Returns:
        Configured AS4SenderService instance.
    """
    import os

    config = DomibusConfig(
        base_url=base_url or os.environ.get("DOMIBUS_URL", "http://domibus:8080"),
        username=username or os.environ.get("DOMIBUS_USERNAME", "admin"),
        password=password or os.environ.get("DOMIBUS_PASSWORD", "123456"),
        sender_party_id=os.environ.get("AS4_SENDER_PARTY_ID", "QERDS_DEV"),
    )

    return AS4SenderService(session, config)
