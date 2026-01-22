"""Tests for AS4 message receiving service.

Covers: REQ-C04 (ETSI interoperability)

Tests cover:
- AS4 message metadata validation
- Payload integrity verification
- Delivery creation from inbound messages
- Evidence event generation (EVT_AS4_RECEIVED)
- Receipt generation for sender acknowledgment
- Error handling for invalid messages
"""

import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from qerds.db.models.base import EventType
from qerds.services.as4_receiver import (
    AS4MessageHandler,
    AS4MessageMetadata,
    AS4MessageType,
    AS4Payload,
    AS4Receipt,
    AS4ReceiveResult,
    AS4ValidationError,
)

# =============================================================================
# Test Data Factories
# =============================================================================


def create_test_metadata(
    message_id: str | None = None,
    conversation_id: str | None = None,
    from_party_id: str | None = None,
    to_party_id: str | None = None,
    service: str = "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
    action: str = "delivery",
    timestamp: datetime | None = None,
    ref_to_message_id: str | None = None,
) -> AS4MessageMetadata:
    """Create test AS4 message metadata."""
    return AS4MessageMetadata(
        message_id=message_id or f"msg-{uuid4()}",
        conversation_id=conversation_id or f"conv-{uuid4()}",
        from_party_id=from_party_id or "external-provider-001",
        to_party_id=to_party_id or "qerds-local-001",
        service=service,
        action=action,
        timestamp=timestamp or datetime.now(UTC),
        ref_to_message_id=ref_to_message_id,
    )


def create_test_payload(
    content_id: str | None = None,
    content_type: str = "application/pdf",
    data: bytes | None = None,
    filename: str | None = None,
) -> AS4Payload:
    """Create test AS4 payload."""
    payload_data = data or b"test document content"
    sha256 = hashlib.sha256(payload_data).hexdigest()
    return AS4Payload(
        content_id=content_id or f"payload-{uuid4()}",
        content_type=content_type,
        data=payload_data,
        sha256=sha256,
        filename=filename or "document.pdf",
    )


def create_xml_envelope_payload(
    recipient_email: str = "recipient@example.com",
    recipient_name: str = "Test Recipient",
    subject: str = "Test Delivery",
) -> AS4Payload:
    """Create test ETSI XML envelope payload."""
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
    <ERDSEnvelope xmlns="urn:etsi:en:319522">
        <RecipientEmail>{recipient_email}</RecipientEmail>
        <RecipientName>{recipient_name}</RecipientName>
        <Subject>{subject}</Subject>
        <JurisdictionProfile>eidas</JurisdictionProfile>
    </ERDSEnvelope>
    """.encode()
    sha256 = hashlib.sha256(xml_content).hexdigest()
    return AS4Payload(
        content_id="envelope",
        content_type="application/xml",
        data=xml_content,
        sha256=sha256,
        filename="envelope.xml",
    )


# =============================================================================
# Unit Tests: AS4MessageType Enum
# =============================================================================


class TestAS4MessageType:
    """Tests for AS4MessageType enum."""

    def test_message_types_defined(self):
        """All expected message types are defined."""
        assert AS4MessageType.SUBMISSION.value == "submission"
        assert AS4MessageType.RELAY.value == "relay"
        assert AS4MessageType.DISPATCH.value == "dispatch"
        assert AS4MessageType.RECEIPT.value == "receipt"
        assert AS4MessageType.ERROR.value == "error"


# =============================================================================
# Unit Tests: Data Classes
# =============================================================================


class TestAS4MessageMetadata:
    """Tests for AS4MessageMetadata dataclass."""

    def test_metadata_is_immutable(self):
        """Metadata cannot be modified after creation."""
        metadata = create_test_metadata()
        with pytest.raises(AttributeError):
            metadata.message_id = "new-id"  # type: ignore

    def test_metadata_stores_all_fields(self):
        """Metadata stores all provided fields."""
        timestamp = datetime.now(UTC)
        metadata = AS4MessageMetadata(
            message_id="msg-123",
            conversation_id="conv-456",
            from_party_id="provider-a",
            to_party_id="provider-b",
            service="test-service",
            action="submission",
            timestamp=timestamp,
            ref_to_message_id="ref-789",
            properties={"key": "value"},
        )

        assert metadata.message_id == "msg-123"
        assert metadata.conversation_id == "conv-456"
        assert metadata.from_party_id == "provider-a"
        assert metadata.to_party_id == "provider-b"
        assert metadata.service == "test-service"
        assert metadata.action == "submission"
        assert metadata.timestamp == timestamp
        assert metadata.ref_to_message_id == "ref-789"
        assert metadata.properties == {"key": "value"}


class TestAS4Payload:
    """Tests for AS4Payload dataclass."""

    def test_payload_is_immutable(self):
        """Payload cannot be modified after creation."""
        payload = create_test_payload()
        with pytest.raises(AttributeError):
            payload.data = b"new data"  # type: ignore

    def test_payload_stores_all_fields(self):
        """Payload stores all provided fields."""
        data = b"test content"
        sha256 = hashlib.sha256(data).hexdigest()
        payload = AS4Payload(
            content_id="cid-001",
            content_type="text/plain",
            data=data,
            sha256=sha256,
            filename="test.txt",
        )

        assert payload.content_id == "cid-001"
        assert payload.content_type == "text/plain"
        assert payload.data == data
        assert payload.sha256 == sha256
        assert payload.filename == "test.txt"


class TestAS4ReceiveResult:
    """Tests for AS4ReceiveResult dataclass."""

    def test_success_result(self):
        """Success result contains expected fields."""
        delivery_id = uuid4()
        event_id = uuid4()
        result = AS4ReceiveResult(
            success=True,
            delivery_id=delivery_id,
            evidence_event_id=event_id,
            receipt_message_id="receipt-001",
        )

        assert result.success is True
        assert result.delivery_id == delivery_id
        assert result.evidence_event_id == event_id
        assert result.receipt_message_id == "receipt-001"
        assert result.error_code is None
        assert result.error_message is None

    def test_failure_result(self):
        """Failure result contains error information."""
        result = AS4ReceiveResult(
            success=False,
            error_code="VALIDATION_ERROR",
            error_message="Invalid message format",
        )

        assert result.success is False
        assert result.delivery_id is None
        assert result.evidence_event_id is None
        assert result.receipt_message_id is None
        assert result.error_code == "VALIDATION_ERROR"
        assert result.error_message == "Invalid message format"


class TestAS4Receipt:
    """Tests for AS4Receipt dataclass."""

    def test_receipt_stores_all_fields(self):
        """Receipt stores all provided fields."""
        timestamp = datetime.now(UTC)
        receipt = AS4Receipt(
            receipt_message_id="receipt-123",
            ref_to_message_id="msg-456",
            timestamp=timestamp,
            receipt_type="delivery",
            digest="abc123",
        )

        assert receipt.receipt_message_id == "receipt-123"
        assert receipt.ref_to_message_id == "msg-456"
        assert receipt.timestamp == timestamp
        assert receipt.receipt_type == "delivery"
        assert receipt.digest == "abc123"


# =============================================================================
# Unit Tests: Validation
# =============================================================================


class TestMetadataValidation:
    """Tests for AS4 message metadata validation."""

    def test_missing_message_id_raises_error(self):
        """Missing message ID raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        metadata = AS4MessageMetadata(
            message_id="",  # Empty
            conversation_id="conv-123",
            from_party_id="provider-a",
            to_party_id="provider-b",
            service="test",
            action="delivery",
            timestamp=datetime.now(UTC),
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_metadata(metadata)

        assert exc.value.code == "MISSING_MESSAGE_ID"

    def test_missing_from_party_raises_error(self):
        """Missing from_party_id raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        metadata = AS4MessageMetadata(
            message_id="msg-123",
            conversation_id="conv-123",
            from_party_id="",  # Empty
            to_party_id="provider-b",
            service="test",
            action="delivery",
            timestamp=datetime.now(UTC),
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_metadata(metadata)

        assert exc.value.code == "MISSING_FROM_PARTY"

    def test_missing_to_party_raises_error(self):
        """Missing to_party_id raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        metadata = AS4MessageMetadata(
            message_id="msg-123",
            conversation_id="conv-123",
            from_party_id="provider-a",
            to_party_id="",  # Empty
            service="test",
            action="delivery",
            timestamp=datetime.now(UTC),
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_metadata(metadata)

        assert exc.value.code == "MISSING_TO_PARTY"

    def test_missing_conversation_id_raises_error(self):
        """Missing conversation_id raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        metadata = AS4MessageMetadata(
            message_id="msg-123",
            conversation_id="",  # Empty
            from_party_id="provider-a",
            to_party_id="provider-b",
            service="test",
            action="delivery",
            timestamp=datetime.now(UTC),
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_metadata(metadata)

        assert exc.value.code == "MISSING_CONVERSATION_ID"

    def test_unsupported_action_raises_error(self):
        """Unsupported action raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata(action="unsupported_action")

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_metadata(metadata)

        assert exc.value.code == "UNSUPPORTED_ACTION"

    def test_supported_actions_pass_validation(self):
        """Supported actions pass validation."""
        handler = AS4MessageHandler(MagicMock())

        supported_actions = ["submission", "delivery", "relay", "dispatch"]
        for action in supported_actions:
            metadata = create_test_metadata(action=action)
            # Should not raise
            handler._validate_metadata(metadata)


class TestPayloadValidation:
    """Tests for AS4 payload validation."""

    def test_empty_payloads_raises_error(self):
        """Empty payload list raises validation error."""
        handler = AS4MessageHandler(MagicMock())

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_payloads([])

        assert exc.value.code == "MISSING_PAYLOAD"

    def test_missing_content_id_raises_error(self):
        """Payload without content_id raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        payload = AS4Payload(
            content_id="",  # Empty
            content_type="text/plain",
            data=b"test",
            sha256=hashlib.sha256(b"test").hexdigest(),
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_payloads([payload])

        assert exc.value.code == "MISSING_CONTENT_ID"

    def test_empty_data_raises_error(self):
        """Payload with empty data raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        payload = AS4Payload(
            content_id="cid-001",
            content_type="text/plain",
            data=b"",  # Empty
            sha256="",
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_payloads([payload])

        assert exc.value.code == "EMPTY_PAYLOAD"

    def test_hash_mismatch_raises_error(self):
        """Payload with incorrect hash raises validation error."""
        handler = AS4MessageHandler(MagicMock())
        payload = AS4Payload(
            content_id="cid-001",
            content_type="text/plain",
            data=b"test content",
            sha256="invalid_hash",  # Wrong hash
        )

        with pytest.raises(AS4ValidationError) as exc:
            handler._validate_payloads([payload])

        assert exc.value.code == "PAYLOAD_INTEGRITY_FAILURE"

    def test_valid_payloads_pass(self):
        """Valid payloads pass validation."""
        handler = AS4MessageHandler(MagicMock())
        payload = create_test_payload()

        # Should not raise
        handler._validate_payloads([payload])


# =============================================================================
# Unit Tests: ETSI XML Parsing
# =============================================================================


class TestETSIXMLParsing:
    """Tests for ETSI XML envelope parsing."""

    def test_parse_xml_extracts_recipient_email(self):
        """Parser extracts recipient email from XML."""
        handler = AS4MessageHandler(MagicMock())
        envelope = create_xml_envelope_payload(recipient_email="test@example.com")

        info = handler._parse_etsi_xml(envelope.data)

        assert info.get("recipient_email") == "test@example.com"

    def test_parse_xml_extracts_recipient_name(self):
        """Parser extracts recipient name from XML."""
        handler = AS4MessageHandler(MagicMock())
        envelope = create_xml_envelope_payload(recipient_name="John Doe")

        info = handler._parse_etsi_xml(envelope.data)

        assert info.get("recipient_name") == "John Doe"

    def test_parse_xml_extracts_subject(self):
        """Parser extracts subject from XML."""
        handler = AS4MessageHandler(MagicMock())
        envelope = create_xml_envelope_payload(subject="Important Document")

        info = handler._parse_etsi_xml(envelope.data)

        assert info.get("subject") == "Important Document"

    def test_parse_invalid_xml_returns_empty(self):
        """Parser returns empty dict for invalid XML."""
        handler = AS4MessageHandler(MagicMock())

        info = handler._parse_etsi_xml(b"not valid xml")

        assert info == {}

    def test_parse_delivery_envelope_with_non_xml_payload(self):
        """parse_delivery_envelope returns defaults for non-XML payloads."""
        handler = AS4MessageHandler(MagicMock())
        payload = create_test_payload(content_type="application/pdf")

        info = handler._parse_delivery_envelope([payload])

        assert info.get("jurisdiction_profile") == "eidas"  # Default


# =============================================================================
# Unit Tests: Receipt Generation
# =============================================================================


class TestReceiptGeneration:
    """Tests for AS4 receipt generation."""

    def test_receipt_has_unique_id(self):
        """Generated receipt has unique message ID."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata()

        receipt1 = handler._generate_receipt(metadata)
        receipt2 = handler._generate_receipt(metadata)

        assert receipt1.receipt_message_id != receipt2.receipt_message_id

    def test_receipt_references_original_message(self):
        """Receipt references the original message ID."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata(message_id="original-msg-123")

        receipt = handler._generate_receipt(metadata)

        assert receipt.ref_to_message_id == "original-msg-123"

    def test_receipt_has_timestamp(self):
        """Receipt has a timestamp."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata()
        before = datetime.now(UTC)

        receipt = handler._generate_receipt(metadata)
        after = datetime.now(UTC)

        assert before <= receipt.timestamp <= after

    def test_receipt_uses_provided_digest(self):
        """Receipt uses provided raw message digest."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata()

        receipt = handler._generate_receipt(metadata, raw_message_digest="provided_digest")

        assert receipt.digest == "provided_digest"

    def test_receipt_generates_digest_if_not_provided(self):
        """Receipt generates digest from message ID if not provided."""
        handler = AS4MessageHandler(MagicMock())
        metadata = create_test_metadata(message_id="test-msg")

        receipt = handler._generate_receipt(metadata)

        expected_digest = hashlib.sha256(b"test-msg").hexdigest()
        assert receipt.digest == expected_digest


# =============================================================================
# Integration Tests: Full Message Processing
# =============================================================================


class TestMessageProcessing:
    """Tests for full AS4 message processing flow."""

    @pytest.mark.asyncio
    async def test_process_valid_message_returns_success(self):
        """Processing valid message returns success result."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payloads = [create_xml_envelope_payload(), create_test_payload()]

        result = await handler.process_inbound_message(metadata, payloads)

        assert result.success is True
        assert result.delivery_id is not None
        assert result.evidence_event_id is not None
        assert result.receipt_message_id is not None

    @pytest.mark.asyncio
    async def test_process_invalid_metadata_returns_failure(self):
        """Processing message with invalid metadata returns failure."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = AS4MessageMetadata(
            message_id="",  # Invalid: empty
            conversation_id="conv-123",
            from_party_id="provider-a",
            to_party_id="provider-b",
            service="test",
            action="delivery",
            timestamp=datetime.now(UTC),
        )
        payloads = [create_test_payload()]

        result = await handler.process_inbound_message(metadata, payloads)

        assert result.success is False
        assert result.error_code == "MISSING_MESSAGE_ID"

    @pytest.mark.asyncio
    async def test_process_invalid_payload_returns_failure(self):
        """Processing message with invalid payload returns failure."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payload = AS4Payload(
            content_id="cid-001",
            content_type="text/plain",
            data=b"test",
            sha256="wrong_hash",  # Invalid
        )

        result = await handler.process_inbound_message(metadata, [payload])

        assert result.success is False
        assert result.error_code == "PAYLOAD_INTEGRITY_FAILURE"

    @pytest.mark.asyncio
    async def test_process_message_creates_delivery(self):
        """Processing message creates a delivery record."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payloads = [create_xml_envelope_payload(), create_test_payload()]

        result = await handler.process_inbound_message(metadata, payloads)

        assert result.success is True
        # Verify session.add was called (for delivery creation)
        assert session.add.called

    @pytest.mark.asyncio
    async def test_process_message_creates_evidence_event(self):
        """Processing message creates EVT_AS4_RECEIVED evidence event."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payloads = [create_test_payload()]

        result = await handler.process_inbound_message(metadata, payloads)

        assert result.success is True
        # Check that an evidence event was added
        add_calls = session.add.call_args_list
        event_added = any(
            hasattr(call.args[0], "event_type")
            and call.args[0].event_type == EventType.EVT_AS4_RECEIVED
            for call in add_calls
            if call.args
        )
        assert event_added

    @pytest.mark.asyncio
    async def test_process_message_commits_transaction(self):
        """Processing message commits the database transaction."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payloads = [create_test_payload()]

        await handler.process_inbound_message(metadata, payloads)

        session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_unexpected_error_returns_internal_error(self):
        """Unexpected error during processing returns INTERNAL_ERROR."""
        session = create_mock_session()
        session.flush.side_effect = Exception("Database error")
        handler = AS4MessageHandler(session)

        metadata = create_test_metadata()
        payloads = [create_test_payload()]

        result = await handler.process_inbound_message(metadata, payloads)

        assert result.success is False
        assert result.error_code == "INTERNAL_ERROR"


class TestRecipientNotification:
    """Tests for recipient notification triggering."""

    @pytest.mark.asyncio
    async def test_trigger_notification_enqueues_job(self):
        """Triggering notification enqueues a notification job."""
        session = create_mock_session()
        handler = AS4MessageHandler(session)
        delivery_id = uuid4()

        # Patch JobQueueService at the import location (inside the function)
        with patch("qerds.services.job_queue.JobQueueService") as mock_job_service_class:
            mock_job_service = AsyncMock()
            mock_job_service_class.return_value = mock_job_service

            await handler.trigger_recipient_notification(delivery_id)

            mock_job_service.enqueue_job.assert_called_once()
            call_kwargs = mock_job_service.enqueue_job.call_args.kwargs
            assert call_kwargs["job_type"] == "notification_send"
            assert call_kwargs["payload"]["delivery_id"] == str(delivery_id)


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_session():
    """Create a mock SQLAlchemy async session for tests.

    Returns:
        Mock async session with standard behaviors.
    """
    session = AsyncMock()

    # Track added objects and assign UUIDs to them
    def track_add(obj):
        """Track added objects and assign UUIDs."""
        # Assign UUIDs to models when they're added
        if hasattr(obj, "delivery_id") and obj.delivery_id is None:
            obj.delivery_id = uuid4()
        if hasattr(obj, "party_id") and obj.party_id is None:
            obj.party_id = uuid4()
        if hasattr(obj, "event_id") and obj.event_id is None:
            obj.event_id = uuid4()

    # Mock party lookup returning None (create new)
    async def mock_execute(query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        return result

    session.execute = mock_execute
    session.add = MagicMock(side_effect=track_add)
    session.flush = AsyncMock()
    session.commit = AsyncMock()

    return session
