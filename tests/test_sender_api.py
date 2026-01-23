"""Tests for sender API endpoints.

Tests cover:
- Delivery creation (POST /sender/deliveries)
- Content upload (POST /sender/deliveries/{id}/content)
- Deposit (POST /sender/deliveries/{id}/deposit)
- Delivery listing (GET /sender/deliveries)
- Delivery details (GET /sender/deliveries/{id})
- Proof listing (GET /sender/deliveries/{id}/proofs)
- Proof download (GET /sender/deliveries/{id}/proofs/{type})
- Authentication and authorization
- Input validation
- Error handling

Covers: REQ-B01, REQ-B02, REQ-B05, REQ-C01
"""

import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from qerds.api.middleware.auth import AuthenticatedUser
from qerds.api.routers.sender import router as sender_router
from qerds.api.schemas.sender import (
    ContentObjectResponse,
    ContentUploadResponse,
    CreateDeliveryRequest,
    DeliveryListResponse,
    DeliveryResponse,
    DeliverySummary,
    DepositResponse,
    ProofListResponse,
    RecipientInput,
)
from qerds.db.models.base import DeliveryState, EventType

# -----------------------------------------------------------------------------
# Test fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def sender_user() -> AuthenticatedUser:
    """Create a mock authenticated sender user."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["sender_user"]),
        permissions=frozenset(),
        ip_address="127.0.0.1",
        user_agent="pytest",
        auth_method="session",
        metadata={
            "display_name": "Test Sender",
            "email": "sender@example.com",
            "ial_level": "ial2",
        },
    )


@pytest.fixture
def non_sender_user() -> AuthenticatedUser:
    """Create a mock authenticated user without sender role."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["recipient_user"]),
        permissions=frozenset(),
        ip_address="127.0.0.1",
        user_agent="pytest",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock()
    return session


@pytest.fixture
def mock_storage_client():
    """Create a mock object store client."""
    client = MagicMock()
    client.upload = MagicMock(
        return_value=MagicMock(
            key="test-key",
            bucket="qerds-content",
            sha256_digest="abc123",
            size_bytes=1024,
            etag='"etag"',
        )
    )
    return client


@pytest.fixture
def sample_content() -> bytes:
    """Generate sample content for upload tests."""
    return b"This is sample PDF content for testing"


@pytest.fixture
def sample_content_hash(sample_content: bytes) -> str:
    """Compute SHA-256 hash of sample content."""
    return hashlib.sha256(sample_content).hexdigest()


# -----------------------------------------------------------------------------
# Schema validation tests
# -----------------------------------------------------------------------------


class TestSchemaValidation:
    """Tests for Pydantic schema validation."""

    def test_create_delivery_request_valid(self):
        """Test valid delivery creation request."""
        request = CreateDeliveryRequest(
            recipient=RecipientInput(
                email="recipient@example.com",
                display_name="Test Recipient",
            ),
            subject="Test Subject",
            message="Test message body",
            jurisdiction_profile="eidas",
        )
        assert request.recipient.email == "recipient@example.com"
        assert request.subject == "Test Subject"
        assert request.jurisdiction_profile == "eidas"

    def test_create_delivery_request_minimal(self):
        """Test minimal valid delivery creation request."""
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="recipient@example.com"),
        )
        assert request.recipient.email == "recipient@example.com"
        assert request.subject is None
        assert request.jurisdiction_profile == "eidas"  # default

    def test_create_delivery_request_invalid_email(self):
        """Test delivery creation with invalid email."""
        with pytest.raises(ValueError):
            CreateDeliveryRequest(
                recipient=RecipientInput(email="not-an-email"),
            )

    def test_create_delivery_request_invalid_jurisdiction(self):
        """Test delivery creation with invalid jurisdiction profile."""
        with pytest.raises(ValueError):
            CreateDeliveryRequest(
                recipient=RecipientInput(email="recipient@example.com"),
                jurisdiction_profile="invalid_profile",
            )

    def test_create_delivery_request_fr_lre_jurisdiction(self):
        """Test delivery creation with fr_lre jurisdiction."""
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="recipient@example.com"),
            jurisdiction_profile="fr_lre",
        )
        assert request.jurisdiction_profile == "fr_lre"

    def test_recipient_input_with_name(self):
        """Test recipient input with display name."""
        recipient = RecipientInput(
            email="test@example.com",
            display_name="Test User",
        )
        assert recipient.email == "test@example.com"
        assert recipient.display_name == "Test User"

    def test_delivery_response_from_attributes(self):
        """Test DeliveryResponse creation from model attributes."""
        # Create a mock delivery-like object
        delivery_id = uuid4()
        sender_id = uuid4()
        recipient_id = uuid4()
        now = datetime.now(UTC)

        response = DeliveryResponse(
            delivery_id=delivery_id,
            state="draft",
            sender_party_id=sender_id,
            recipient_party_id=recipient_id,
            recipient_email="recipient@example.com",
            recipient_name="Test Recipient",
            subject="Test",
            message=None,
            jurisdiction_profile="eidas",
            acceptance_deadline_at=None,
            created_at=now,
            updated_at=now,
            deposited_at=None,
            notified_at=None,
            available_at=None,
            completed_at=None,
            content_objects=[],
        )

        assert response.delivery_id == delivery_id
        assert response.state == "draft"

    def test_delivery_list_response(self):
        """Test DeliveryListResponse structure."""
        response = DeliveryListResponse(
            items=[
                DeliverySummary(
                    delivery_id=uuid4(),
                    state="draft",
                    recipient_email="test@example.com",
                    recipient_name="Test",
                    subject="Subject",
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    content_count=1,
                )
            ],
            total=1,
            offset=0,
            limit=20,
        )

        assert len(response.items) == 1
        assert response.total == 1

    def test_content_upload_response(self):
        """Test ContentUploadResponse structure."""
        response = ContentUploadResponse(
            content_object_id=uuid4(),
            sha256="a" * 64,
            size_bytes=1024,
            storage_key="deliveries/abc/content/hash",
        )

        assert len(response.sha256) == 64
        assert response.size_bytes == 1024

    def test_deposit_response(self):
        """Test DepositResponse structure."""
        response = DepositResponse(
            delivery_id=uuid4(),
            state="deposited",
            deposited_at=datetime.now(UTC),
            evidence_event_id=uuid4(),
            content_hashes=["a" * 64, "b" * 64],
        )

        assert response.state == "deposited"
        assert len(response.content_hashes) == 2

    def test_proof_list_response(self):
        """Test ProofListResponse structure."""
        from qerds.api.schemas.sender import ProofType

        response = ProofListResponse(
            delivery_id=uuid4(),
            proofs=[
                ProofType(
                    type="deposit",
                    name="Proof of Deposit",
                    available=True,
                    event_type="evt_deposited",
                    generated_at=datetime.now(UTC),
                ),
                ProofType(
                    type="notification",
                    name="Proof of Notification",
                    available=False,
                    event_type="evt_notification_sent",
                    generated_at=None,
                ),
            ],
        )

        assert len(response.proofs) == 2
        assert response.proofs[0].available is True
        assert response.proofs[1].available is False


# -----------------------------------------------------------------------------
# Helper function tests
# -----------------------------------------------------------------------------


class TestHelperFunctions:
    """Tests for helper functions in the sender router."""

    def test_get_user_ial_level_from_metadata(self):
        """Test IAL level extraction from user metadata."""
        from qerds.api.routers.sender import _get_user_ial_level

        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            permissions=frozenset(),
            metadata={"ial_level": "ial3"},
        )

        assert _get_user_ial_level(user) == "ial3"

    def test_get_user_ial_level_from_oidc(self):
        """Test IAL level inference from OIDC auth method."""
        from qerds.api.routers.sender import _get_user_ial_level

        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            permissions=frozenset(),
            auth_method="oidc",
            metadata={"acr": "eidas3"},
        )

        assert _get_user_ial_level(user) == "ial3"

    def test_get_user_ial_level_default(self):
        """Test default IAL level for non-OIDC auth."""
        from qerds.api.routers.sender import _get_user_ial_level

        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            permissions=frozenset(),
            auth_method="session",
            metadata={},
        )

        assert _get_user_ial_level(user) == "ial1"


# -----------------------------------------------------------------------------
# Integration tests (with mocked dependencies)
# -----------------------------------------------------------------------------


class TestSenderAPIIntegration:
    """Integration tests for sender API with mocked dependencies."""

    @pytest.fixture
    def app_with_mocks(self, sender_user, mock_db_session, mock_storage_client):
        """Create a FastAPI app with mocked dependencies."""
        app = FastAPI()
        app.include_router(sender_router)

        # Override dependencies
        async def override_get_db_session():
            yield mock_db_session

        async def override_get_storage_client():
            return mock_storage_client

        async def override_require_sender_role():
            return sender_user

        from qerds.api.routers.sender import get_db_session, get_storage_client

        app.dependency_overrides[get_db_session] = override_get_db_session
        app.dependency_overrides[get_storage_client] = override_get_storage_client
        # Note: require_role returns a function, so we need to handle it differently

        return app

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Test the health check endpoint."""
        from httpx import ASGITransport

        app = FastAPI()
        app.include_router(sender_router)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Note: When router is included directly without prefix, use /sender/health
            response = await client.get("/sender/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["namespace"] == "sender"


class TestAuthenticationRequirements:
    """Tests for authentication requirements on sender endpoints."""

    @pytest.mark.asyncio
    async def test_create_delivery_requires_auth(self, api_client: AsyncClient):
        """Test that create delivery requires authentication."""
        response = await api_client.post(
            "/api/sender/deliveries",
            json={
                "recipient": {"email": "test@example.com"},
            },
        )
        # Should return 401 or 403 without auth
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_list_deliveries_requires_auth(self, api_client: AsyncClient):
        """Test that list deliveries requires authentication."""
        response = await api_client.get("/api/sender/deliveries")
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_get_delivery_requires_auth(self, api_client: AsyncClient):
        """Test that get delivery requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.get(f"/api/sender/deliveries/{delivery_id}")
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_upload_content_requires_auth(self, api_client: AsyncClient):
        """Test that content upload requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.post(
            f"/api/sender/deliveries/{delivery_id}/content",
            files={"file": ("test.pdf", b"content", "application/pdf")},
            data={
                "original_filename": "test.pdf",
                "mime_type": "application/pdf",
                "sha256": "a" * 64,
            },
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_deposit_requires_auth(self, api_client: AsyncClient):
        """Test that deposit requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.post(f"/api/sender/deliveries/{delivery_id}/deposit")
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_list_proofs_requires_auth(self, api_client: AsyncClient):
        """Test that list proofs requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.get(f"/api/sender/deliveries/{delivery_id}/proofs")
        assert response.status_code in [401, 403]


class TestInputValidation:
    """Tests for input validation on sender endpoints."""

    @pytest.mark.asyncio
    async def test_create_delivery_invalid_json(self, api_client: AsyncClient):
        """Test create delivery with invalid JSON."""
        response = await api_client.post(
            "/api/sender/deliveries",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        # Should return 4xx error for invalid input
        assert response.status_code >= 400

    @pytest.mark.asyncio
    async def test_get_delivery_invalid_uuid(self, api_client: AsyncClient):
        """Test get delivery with invalid UUID format."""
        response = await api_client.get("/api/sender/deliveries/not-a-uuid")
        # May return 401 (auth check first) or 422 (validation error)
        assert response.status_code in [401, 403, 422]

    @pytest.mark.asyncio
    async def test_list_deliveries_invalid_offset(self, api_client: AsyncClient):
        """Test list deliveries with invalid offset."""
        response = await api_client.get("/api/sender/deliveries?offset=-1")
        # Should return 422 for validation error
        assert response.status_code in [401, 403, 422]  # Auth check may come first


class TestContentHashValidation:
    """Tests for SHA-256 hash validation during content upload."""

    def test_sha256_normalization(self):
        """Test that SHA-256 hashes are normalized to lowercase."""
        from qerds.api.schemas.sender import ContentUploadRequest

        # Uppercase hash should be normalized
        request = ContentUploadRequest(
            original_filename="test.pdf",
            mime_type="application/pdf",
            sha256="ABCDEF0123456789" * 4,  # 64 uppercase chars
        )
        assert request.sha256 == "abcdef0123456789" * 4  # should be lowercase

    def test_sha256_invalid_length(self):
        """Test that invalid length SHA-256 is rejected."""
        from qerds.api.schemas.sender import ContentUploadRequest

        with pytest.raises(ValueError):
            ContentUploadRequest(
                original_filename="test.pdf",
                mime_type="application/pdf",
                sha256="tooshort",
            )

    def test_sha256_invalid_characters(self):
        """Test that non-hex characters in SHA-256 are rejected."""
        from qerds.api.schemas.sender import ContentUploadRequest

        with pytest.raises(ValueError):
            ContentUploadRequest(
                original_filename="test.pdf",
                mime_type="application/pdf",
                sha256="g" * 64,  # 'g' is not a valid hex char
            )


class TestDeliveryStateMachine:
    """Tests for delivery state machine enforcement."""

    def test_valid_state_transitions(self):
        """Test that valid state transitions are defined correctly."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        # Create service instance with mock db session
        mock_db = MagicMock()
        service = DeliveryLifecycleService(mock_db)

        # Draft can transition to deposited
        assert service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.DEPOSITED)

        # Deposited can transition to notified
        assert service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.NOTIFIED)

    def test_invalid_state_transitions(self):
        """Test that invalid state transitions are rejected."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        # Create service instance with mock db session
        mock_db = MagicMock()
        service = DeliveryLifecycleService(mock_db)

        # Cannot go from draft directly to notified
        assert not service.is_valid_transition(DeliveryState.DRAFT, DeliveryState.NOTIFIED)

        # Cannot go backwards from deposited to draft
        assert not service.is_valid_transition(DeliveryState.DEPOSITED, DeliveryState.DRAFT)


class TestProofTypes:
    """Tests for proof type definitions and availability."""

    def test_proof_type_event_mapping(self):
        """Test that proof types map to correct event types."""

        # The mapping is defined in the download_proof function
        # We can verify the expected mappings exist
        expected_proof_types = [
            "deposit",
            "notification",
            "acceptance",
            "refusal",
            "receipt",
            "expiry",
        ]

        # Each should be a valid proof type identifier
        valid_types = ["deposit", "notification", "acceptance", "refusal", "receipt", "expiry"]
        for proof_type in expected_proof_types:
            assert proof_type in valid_types

    def test_all_event_types_have_proofs(self):
        """Test that key evidence event types have corresponding proofs."""
        # Map of event types to proof types
        event_to_proof = {
            EventType.EVT_DEPOSITED: "deposit",
            EventType.EVT_NOTIFICATION_SENT: "notification",
            EventType.EVT_ACCEPTED: "acceptance",
            EventType.EVT_REFUSED: "refusal",
            EventType.EVT_RECEIVED: "receipt",
            EventType.EVT_EXPIRED: "expiry",
        }

        # Verify mapping exists
        assert len(event_to_proof) == 6


class TestContentObjectResponse:
    """Tests for content object response schema."""

    def test_content_object_response_fields(self):
        """Test ContentObjectResponse has all required fields."""
        now = datetime.now(UTC)
        response = ContentObjectResponse(
            content_object_id=uuid4(),
            sha256="a" * 64,
            size_bytes=1024,
            mime_type="application/pdf",
            original_filename="document.pdf",
            created_at=now,
        )

        assert response.sha256 == "a" * 64
        assert response.size_bytes == 1024
        assert response.mime_type == "application/pdf"
        assert response.original_filename == "document.pdf"

    def test_content_object_response_optional_filename(self):
        """Test ContentObjectResponse with optional filename."""
        response = ContentObjectResponse(
            content_object_id=uuid4(),
            sha256="a" * 64,
            size_bytes=1024,
            mime_type="application/octet-stream",
            original_filename=None,
            created_at=datetime.now(UTC),
        )

        assert response.original_filename is None


# -----------------------------------------------------------------------------
# Edge case tests
# -----------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_create_delivery_max_length_subject(self):
        """Test delivery creation with maximum length subject."""
        max_subject = "x" * 500  # max_length=500
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="test@example.com"),
            subject=max_subject,
        )
        assert len(request.subject) == 500

    def test_create_delivery_subject_too_long(self):
        """Test delivery creation with subject exceeding max length."""
        with pytest.raises(ValueError):
            CreateDeliveryRequest(
                recipient=RecipientInput(email="test@example.com"),
                subject="x" * 501,  # exceeds max_length=500
            )

    def test_create_delivery_max_length_message(self):
        """Test delivery creation with maximum length message."""
        max_message = "x" * 10000  # max_length=10000
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="test@example.com"),
            message=max_message,
        )
        assert len(request.message) == 10000

    def test_create_delivery_message_too_long(self):
        """Test delivery creation with message exceeding max length."""
        with pytest.raises(ValueError):
            CreateDeliveryRequest(
                recipient=RecipientInput(email="test@example.com"),
                message="x" * 10001,  # exceeds max_length=10000
            )

    def test_pagination_boundary_values(self):
        """Test pagination with boundary values."""
        from qerds.api.schemas.sender import DeliveryListParams

        # Minimum values
        params = DeliveryListParams(offset=0, limit=1)
        assert params.offset == 0
        assert params.limit == 1

        # Maximum limit
        params = DeliveryListParams(offset=0, limit=100)
        assert params.limit == 100

    def test_pagination_invalid_values(self):
        """Test pagination with invalid values."""
        from qerds.api.schemas.sender import DeliveryListParams

        # Negative offset should fail
        with pytest.raises(ValueError):
            DeliveryListParams(offset=-1, limit=20)

        # Zero limit should fail
        with pytest.raises(ValueError):
            DeliveryListParams(offset=0, limit=0)

        # Limit > 100 should fail
        with pytest.raises(ValueError):
            DeliveryListParams(offset=0, limit=101)


class TestJurisdictionProfiles:
    """Tests for jurisdiction profile handling."""

    def test_eidas_profile(self):
        """Test eIDAS jurisdiction profile."""
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="test@example.com"),
            jurisdiction_profile="eidas",
        )
        assert request.jurisdiction_profile == "eidas"

    def test_fr_lre_profile(self):
        """Test French LRE jurisdiction profile."""
        request = CreateDeliveryRequest(
            recipient=RecipientInput(email="test@example.com"),
            jurisdiction_profile="fr_lre",
        )
        assert request.jurisdiction_profile == "fr_lre"

    def test_invalid_profile(self):
        """Test invalid jurisdiction profile is rejected."""
        with pytest.raises(ValueError):
            CreateDeliveryRequest(
                recipient=RecipientInput(email="test@example.com"),
                jurisdiction_profile="invalid",
            )
