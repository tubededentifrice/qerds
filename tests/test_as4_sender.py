"""Tests for AS4 sender service.

Covers: REQ-C04 (interoperability profile)

Test Categories:
1. AS4MessageBuilder - message structure construction
2. DomibusClient - HTTP client behavior and error handling
3. AS4SenderService - end-to-end message sending
4. Evidence event generation
5. Receipt processing
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from qerds.db.models.base import ActorType, EventType
from qerds.services.as4_sender import (
    AS4ErrorCode,
    AS4MessageBuilder,
    AS4MessagePayload,
    AS4MessageResult,
    AS4MessageStatus,
    AS4Receipt,
    AS4SenderService,
    DomibusClient,
    DomibusConfig,
    create_as4_sender_service,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def domibus_config() -> DomibusConfig:
    """Create a test Domibus configuration."""
    return DomibusConfig(
        base_url="http://localhost:8080",
        username="admin",
        password="test_password",  # noqa: S106 - test credential
        timeout=10,
        sender_party_id="QERDS_TEST",
        service="urn:eu:europa:ec:qerds:registered-delivery",
        action="DeliverMessage",
    )


@pytest.fixture
def sample_payload() -> AS4MessagePayload:
    """Create a sample AS4 message payload."""
    return AS4MessagePayload(
        delivery_id=uuid4(),
        sender_party_id="QERDS_TEST",
        receiver_party_id="EXTERNAL_PROVIDER",
        receiver_party_id_type="urn:oasis:names:tc:ebcore:partyid-type:unregistered",
        content=b"Test encrypted content",
        content_type="application/octet-stream",
        metadata={"jurisdiction": "eidas"},
        original_sender_name="Jean Dupont",
        recipient_email="recipient@example.com",
    )


@pytest.fixture
def mock_session() -> AsyncMock:
    """Create a mock SQLAlchemy async session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock()
    return session


# =============================================================================
# TEST CLASS: AS4MessageBuilder
# =============================================================================


class TestAS4MessageBuilder:
    """Tests for AS4 message structure construction."""

    def test_build_submission_request_structure(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify the basic structure of the submission request."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        # Check top-level structure
        assert "userMessage" in request
        user_message = request["userMessage"]

        assert "partyInfo" in user_message
        assert "collaborationInfo" in user_message
        assert "messageProperties" in user_message
        assert "payloadInfo" in user_message

    def test_party_info_contains_sender_and_receiver(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify party information is correctly constructed."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        party_info = request["userMessage"]["partyInfo"]

        # Check sender (from)
        assert "from" in party_info
        assert party_info["from"]["partyId"]["value"] == domibus_config.sender_party_id
        assert party_info["from"]["partyId"]["type"] == domibus_config.sender_party_id_type
        assert "initiator" in party_info["from"]["role"]

        # Check receiver (to)
        assert "to" in party_info
        assert party_info["to"]["partyId"]["value"] == sample_payload.receiver_party_id
        assert party_info["to"]["partyId"]["type"] == sample_payload.receiver_party_id_type
        assert "responder" in party_info["to"]["role"]

    def test_collaboration_info_has_service_and_action(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify collaboration information contains service and action."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        collab_info = request["userMessage"]["collaborationInfo"]

        assert collab_info["service"]["value"] == domibus_config.service
        assert collab_info["service"]["type"] == domibus_config.service_type
        assert collab_info["action"] == domibus_config.action
        assert "conversationId" in collab_info
        assert collab_info["conversationId"]  # Non-empty

    def test_message_properties_include_delivery_id(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify message properties include delivery ID."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        msg_props = request["userMessage"]["messageProperties"]["property"]

        # Find deliveryId property
        delivery_id_prop = next(
            (p for p in msg_props if p["name"] == "deliveryId"),
            None,
        )

        assert delivery_id_prop is not None
        assert delivery_id_prop["value"] == str(sample_payload.delivery_id)

    def test_message_properties_include_timestamp(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify message properties include timestamp."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        msg_props = request["userMessage"]["messageProperties"]["property"]

        timestamp_prop = next(
            (p for p in msg_props if p["name"] == "timestamp"),
            None,
        )

        assert timestamp_prop is not None
        # Should be an ISO format timestamp
        datetime.fromisoformat(timestamp_prop["value"])  # Will raise if invalid

    def test_message_properties_include_original_sender(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify message properties include original sender when provided."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        msg_props = request["userMessage"]["messageProperties"]["property"]

        sender_prop = next(
            (p for p in msg_props if p["name"] == "originalSender"),
            None,
        )

        assert sender_prop is not None
        assert sender_prop["value"] == sample_payload.original_sender_name

    def test_message_properties_include_final_recipient(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify message properties include final recipient when provided."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        msg_props = request["userMessage"]["messageProperties"]["property"]

        recipient_prop = next(
            (p for p in msg_props if p["name"] == "finalRecipient"),
            None,
        )

        assert recipient_prop is not None
        assert recipient_prop["value"] == sample_payload.recipient_email

    def test_message_properties_include_custom_metadata(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify custom metadata is included with qerds_ prefix."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        msg_props = request["userMessage"]["messageProperties"]["property"]

        # Check for jurisdiction metadata
        jurisdiction_prop = next(
            (p for p in msg_props if p["name"] == "qerds_jurisdiction"),
            None,
        )

        assert jurisdiction_prop is not None
        assert jurisdiction_prop["value"] == "eidas"

    def test_payload_info_contains_content(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify payload info contains the content."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        payload_info = request["userMessage"]["payloadInfo"]

        assert "partInfo" in payload_info
        assert len(payload_info["partInfo"]) == 1

        part = payload_info["partInfo"][0]
        assert "href" in part
        assert "binaryData" in part

        # Verify content is base64 encoded
        encoded_content = part["binaryData"]["value"]
        decoded = base64.b64decode(encoded_content)
        assert decoded == sample_payload.content

    def test_payload_info_contains_mime_type(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify payload info contains MIME type."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        part = request["userMessage"]["payloadInfo"]["partInfo"][0]
        properties = part["partProperties"]["property"]

        mime_prop = next(
            (p for p in properties if p["name"] == "MimeType"),
            None,
        )

        assert mime_prop is not None
        assert mime_prop["value"] == sample_payload.content_type

    def test_payload_info_contains_content_hash(
        self,
        domibus_config: DomibusConfig,
        sample_payload: AS4MessagePayload,
    ):
        """Verify payload info contains content hash for integrity."""
        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(sample_payload)

        part = request["userMessage"]["payloadInfo"]["partInfo"][0]
        properties = part["partProperties"]["property"]

        hash_prop = next(
            (p for p in properties if p["name"] == "ContentHash"),
            None,
        )

        expected_hash = hashlib.sha256(sample_payload.content).hexdigest()

        assert hash_prop is not None
        assert hash_prop["value"] == expected_hash

    def test_build_without_optional_fields(self, domibus_config: DomibusConfig):
        """Verify message can be built without optional fields."""
        payload = AS4MessagePayload(
            delivery_id=uuid4(),
            sender_party_id="QERDS_TEST",
            receiver_party_id="EXTERNAL_PROVIDER",
            receiver_party_id_type="urn:oasis:names:tc:ebcore:partyid-type:unregistered",
            content=b"Test content",
            content_type="application/octet-stream",
            # No optional fields
        )

        builder = AS4MessageBuilder(domibus_config)
        request = builder.build_submission_request(payload)

        # Should still have required properties
        msg_props = request["userMessage"]["messageProperties"]["property"]
        prop_names = [p["name"] for p in msg_props]

        assert "deliveryId" in prop_names
        assert "timestamp" in prop_names
        # Optional fields should not be present
        assert "originalSender" not in prop_names
        assert "finalRecipient" not in prop_names


# =============================================================================
# TEST CLASS: DomibusClient
# =============================================================================


class TestDomibusClient:
    """Tests for Domibus HTTP client behavior."""

    @pytest.mark.asyncio
    async def test_submit_message_success(self, domibus_config: DomibusConfig):
        """Test successful message submission."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "messageId": "msg-123",
            "domibusMessageId": "dom-456",
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                result = await client.submit_message({"test": "data"})

            assert result.success is True
            assert result.message_id == "msg-123"
            assert result.domibus_message_id == "dom-456"
            assert result.status == AS4MessageStatus.SUBMITTED

    @pytest.mark.asyncio
    async def test_submit_message_authentication_error(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test handling of authentication errors."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                result = await client.submit_message({"test": "data"})

            assert result.success is False
            assert result.error_code == AS4ErrorCode.AUTHENTICATION_ERROR
            assert result.status == AS4MessageStatus.FAILED

    @pytest.mark.asyncio
    async def test_submit_message_validation_error(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test handling of validation errors."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid message format"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                result = await client.submit_message({"test": "data"})

            assert result.success is False
            assert result.error_code == AS4ErrorCode.VALIDATION_ERROR
            assert "Invalid message format" in result.error_message

    @pytest.mark.asyncio
    async def test_submit_message_connection_error(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test handling of connection errors."""
        import httpx

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                result = await client.submit_message({"test": "data"})

            assert result.success is False
            assert result.error_code == AS4ErrorCode.CONNECTION_ERROR
            assert "Connection" in result.error_message

    @pytest.mark.asyncio
    async def test_submit_message_timeout_error(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test handling of timeout errors."""
        import httpx

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("Request timed out"))
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                result = await client.submit_message({"test": "data"})

            assert result.success is False
            assert result.error_code == AS4ErrorCode.TIMEOUT_ERROR

    @pytest.mark.asyncio
    async def test_client_not_initialized(self, domibus_config: DomibusConfig):
        """Test error when client is used without context manager."""
        client = DomibusClient(domibus_config)
        # Don't use context manager

        result = await client.submit_message({"test": "data"})

        assert result.success is False
        assert result.error_code == AS4ErrorCode.CONNECTION_ERROR
        assert "not initialized" in result.error_message

    @pytest.mark.asyncio
    async def test_get_message_status_acknowledged(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test getting message status - acknowledged."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"messageStatus": "ACKNOWLEDGED"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                status = await client.get_message_status("msg-123")

            assert status == AS4MessageStatus.ACKNOWLEDGED

    @pytest.mark.asyncio
    async def test_get_message_status_pending(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test getting message status - pending."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"messageStatus": "SEND_ENQUEUED"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                status = await client.get_message_status("msg-123")

            assert status == AS4MessageStatus.PENDING

    @pytest.mark.asyncio
    async def test_get_message_status_failed(
        self,
        domibus_config: DomibusConfig,
    ):
        """Test getting message status - failed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"messageStatus": "SEND_FAILURE"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client

            async with DomibusClient(domibus_config) as client:
                client._client = mock_client
                status = await client.get_message_status("msg-123")

            assert status == AS4MessageStatus.FAILED


# =============================================================================
# TEST CLASS: AS4SenderService
# =============================================================================


class TestAS4SenderService:
    """Tests for the AS4 sender service."""

    @pytest.mark.asyncio
    async def test_send_delivery_success(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Test successful delivery sending."""
        delivery_id = uuid4()
        content = b"Test encrypted content"

        # Mock successful submission
        mock_result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            # Patch the context manager
            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                result = await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=content,
                )

        assert result.success is True
        assert result.message_id == "msg-123"

        # Verify evidence event was recorded
        mock_session.add.assert_called()
        mock_session.flush.assert_called()

    @pytest.mark.asyncio
    async def test_send_delivery_records_evidence_event(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Test that EVT_AS4_SENT event is recorded."""
        delivery_id = uuid4()
        content = b"Test content"

        mock_result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=content,
                )

        # Check that an evidence event was added
        add_calls = mock_session.add.call_args_list
        assert len(add_calls) >= 1

        # Verify the event has correct attributes
        event = add_calls[0][0][0]
        assert event.delivery_id == delivery_id
        assert event.event_type == EventType.EVT_AS4_SENT
        assert event.actor_type == ActorType.SYSTEM

    @pytest.mark.asyncio
    async def test_send_delivery_with_metadata(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Test sending delivery with custom metadata."""
        delivery_id = uuid4()
        content = b"Test content"
        metadata = {"jurisdiction": "fr_lre", "priority": "high"}

        mock_result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_submit:
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=content,
                    metadata=metadata,
                )

            # Verify the submission request was made
            mock_submit.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_delivery_failure_records_error_event(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Test that failed delivery still records evidence event with error."""
        delivery_id = uuid4()
        content = b"Test content"

        mock_result = AS4MessageResult(
            success=False,
            message_id=None,
            status=AS4MessageStatus.FAILED,
            submission_time=datetime.now(UTC),
            error_code=AS4ErrorCode.CONNECTION_ERROR,
            error_message="Connection refused",
            domibus_message_id=None,
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                result = await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=content,
                )

        assert result.success is False
        assert result.error_code == AS4ErrorCode.CONNECTION_ERROR

        # Check that evidence event still recorded
        mock_session.add.assert_called()

        event = mock_session.add.call_args_list[0][0][0]
        assert event.event_metadata.get("error_code") == "connection_error"

    @pytest.mark.asyncio
    async def test_check_delivery_status(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Test checking delivery status."""
        with patch.object(
            DomibusClient,
            "get_message_status",
            new_callable=AsyncMock,
            return_value=AS4MessageStatus.ACKNOWLEDGED,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                status = await service.check_delivery_status("msg-123")

        assert status == AS4MessageStatus.ACKNOWLEDGED


# =============================================================================
# TEST CLASS: Evidence Event Metadata
# =============================================================================


class TestEvidenceEventMetadata:
    """Tests for evidence event metadata content."""

    @pytest.mark.asyncio
    async def test_event_metadata_includes_message_ids(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Verify event metadata includes AS4 and Domibus message IDs."""
        delivery_id = uuid4()

        mock_result = AS4MessageResult(
            success=True,
            message_id="as4-msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-msg-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=b"test",
                )

        event = mock_session.add.call_args_list[0][0][0]
        assert event.event_metadata["as4_message_id"] == "as4-msg-123"
        assert event.event_metadata["domibus_message_id"] == "dom-msg-456"

    @pytest.mark.asyncio
    async def test_event_metadata_includes_content_hash(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Verify event metadata includes content hash for integrity."""
        delivery_id = uuid4()
        content = b"Test content for hashing"
        expected_hash = hashlib.sha256(content).hexdigest()

        mock_result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=content,
                )

        event = mock_session.add.call_args_list[0][0][0]
        assert event.event_metadata["content_hash"] == expected_hash

    @pytest.mark.asyncio
    async def test_event_metadata_includes_qualification_status(
        self,
        mock_session: AsyncMock,
        domibus_config: DomibusConfig,
    ):
        """Verify event metadata marks non-qualified status."""
        delivery_id = uuid4()

        mock_result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with patch.object(
            DomibusClient,
            "submit_message",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            service = AS4SenderService(mock_session, domibus_config)

            with (
                patch.object(
                    DomibusClient,
                    "__aenter__",
                    return_value=DomibusClient(domibus_config),
                ),
                patch.object(DomibusClient, "__aexit__", return_value=None),
            ):
                await service.send_delivery(
                    delivery_id=delivery_id,
                    receiver_party_id="EXTERNAL_PROVIDER",
                    content=b"test",
                )

        event = mock_session.add.call_args_list[0][0][0]
        assert event.event_metadata["qualification_status"] == "non_qualified"
        assert "Development mode" in event.event_metadata["qualification_reason"]


# =============================================================================
# TEST CLASS: Factory Function
# =============================================================================


class TestFactoryFunction:
    """Tests for the factory function."""

    def test_create_as4_sender_service_with_defaults(
        self,
        mock_session: AsyncMock,
    ):
        """Test creating service with default configuration."""
        with patch.dict(
            "os.environ",
            {
                "DOMIBUS_URL": "http://test-domibus:8080",
                "DOMIBUS_USERNAME": "test_user",
                "DOMIBUS_PASSWORD": "test_pass",
                "AS4_SENDER_PARTY_ID": "TEST_PARTY",
            },
        ):
            service = create_as4_sender_service(mock_session)

        assert service._config.base_url == "http://test-domibus:8080"
        assert service._config.username == "test_user"
        assert service._config.sender_party_id == "TEST_PARTY"

    def test_create_as4_sender_service_with_overrides(
        self,
        mock_session: AsyncMock,
    ):
        """Test creating service with parameter overrides."""
        test_password = "custom_pass"  # noqa: S105 - test credential
        service = create_as4_sender_service(
            mock_session,
            base_url="http://custom-domibus:9090",
            username="custom_user",
            password=test_password,
        )

        assert service._config.base_url == "http://custom-domibus:9090"
        assert service._config.username == "custom_user"
        assert service._config.password == test_password


# =============================================================================
# TEST CLASS: Data Classes
# =============================================================================


class TestDataClasses:
    """Tests for data class immutability and attributes."""

    def test_as4_message_result_immutability(self):
        """Verify AS4MessageResult is immutable."""
        result = AS4MessageResult(
            success=True,
            message_id="msg-123",
            status=AS4MessageStatus.SUBMITTED,
            submission_time=datetime.now(UTC),
            error_code=None,
            error_message=None,
            domibus_message_id="dom-456",
        )

        with pytest.raises(AttributeError):
            result.success = False  # type: ignore

    def test_as4_receipt_immutability(self):
        """Verify AS4Receipt is immutable."""
        receipt = AS4Receipt(
            original_message_id="msg-123",
            receipt_time=datetime.now(UTC),
            receipt_type="delivery",
            receipt_content=b"receipt data",
            sender_party_id="SENDER",
            receiver_party_id="RECEIVER",
        )

        with pytest.raises(AttributeError):
            receipt.receipt_type = "error"  # type: ignore

    def test_domibus_config_defaults(self):
        """Verify DomibusConfig has sensible defaults."""
        config = DomibusConfig(
            base_url="http://localhost:8080",
            username="admin",
            password="secret",  # noqa: S106 - test credential
        )

        assert config.timeout == 30
        assert config.sender_party_id == "QERDS_DEV"
        assert "qerds" in config.service.lower()
        assert config.action == "DeliverMessage"


# =============================================================================
# TEST CLASS: Error Codes
# =============================================================================


class TestErrorCodes:
    """Tests for error code enum values."""

    def test_all_error_codes_have_values(self):
        """Verify all error codes have string values."""
        for error_code in AS4ErrorCode:
            assert isinstance(error_code.value, str)
            assert len(error_code.value) > 0

    def test_all_message_statuses_have_values(self):
        """Verify all message statuses have string values."""
        for status in AS4MessageStatus:
            assert isinstance(status.value, str)
            assert len(status.value) > 0
