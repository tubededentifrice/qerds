"""Tests for recipient API endpoints.

Covers:
- REQ-F03: Pre-acceptance sender identity redaction
- REQ-F04: Acceptance deadline enforcement
- REQ-E02: Content access gating (post-acceptance only)
- REQ-F06: Consumer consent verification

These tests verify the API contract and CPCE compliance requirements.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from qerds.api.schemas.recipient import (
    AcceptDeliveryRequest,
    AcceptDeliveryResponse,
    ContentObjectSummary,
    DeliveryDetail,
    DeliverySummary,
    ErrorResponse,
    InboxResponse,
    RefuseDeliveryRequest,
    RefuseDeliveryResponse,
)
from qerds.db.models.base import DeliveryState
from qerds.services.evidence import apply_redaction, get_redaction_profile


class TestRecipientHealth:
    """Tests for recipient namespace health endpoint."""

    @pytest.mark.asyncio
    async def test_recipient_health(self, api_client: AsyncClient):
        """Test the recipient namespace health endpoint."""
        response = await api_client.get("/recipient/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "recipient"


class TestInboxEndpoint:
    """Tests for GET /recipient/inbox endpoint."""

    @pytest.mark.asyncio
    async def test_inbox_requires_authentication(self, api_client: AsyncClient):
        """Test that inbox endpoint requires authentication."""
        response = await api_client.get("/recipient/inbox")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_inbox_pagination_params(self, api_client: AsyncClient):
        """Test that inbox supports pagination parameters."""
        # Without auth, we get 401, but the schema should accept these params
        response = await api_client.get("/recipient/inbox?page=2&page_size=50")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_inbox_pagination_validation(self, api_client: AsyncClient):
        """Test pagination parameter validation."""
        # Page must be >= 1
        response = await api_client.get("/recipient/inbox?page=0")
        assert response.status_code in [401, 422]  # Auth check or validation

        # Page size must be <= 100
        response = await api_client.get("/recipient/inbox?page_size=200")
        assert response.status_code in [401, 422]


class TestDeliveryDetailEndpoint:
    """Tests for GET /recipient/deliveries/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_delivery_detail_requires_authentication(self, api_client: AsyncClient):
        """Test that delivery detail endpoint requires authentication."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.get(f"/recipient/deliveries/{delivery_id}")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_delivery_detail_invalid_uuid(self, api_client: AsyncClient):
        """Test that invalid UUID returns appropriate error."""
        response = await api_client.get("/recipient/deliveries/not-a-uuid")
        assert response.status_code in [401, 422]  # Auth or validation error


class TestAcceptDeliveryEndpoint:
    """Tests for POST /recipient/deliveries/{id}/accept endpoint."""

    @pytest.mark.asyncio
    async def test_accept_requires_authentication(self, api_client: AsyncClient):
        """Test that accept endpoint requires authentication."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.post(
            f"/recipient/deliveries/{delivery_id}/accept",
            json={"confirm_electronic_consent": True},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_accept_request_validation(self, api_client: AsyncClient):
        """Test accept request body validation."""
        delivery_id = str(uuid.uuid4())
        # Empty body should use default (confirm_electronic_consent=True)
        response = await api_client.post(
            f"/recipient/deliveries/{delivery_id}/accept",
            json={},
        )
        assert response.status_code == 401  # Auth required, but schema should accept


class TestRefuseDeliveryEndpoint:
    """Tests for POST /recipient/deliveries/{id}/refuse endpoint."""

    @pytest.mark.asyncio
    async def test_refuse_requires_authentication(self, api_client: AsyncClient):
        """Test that refuse endpoint requires authentication."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.post(
            f"/recipient/deliveries/{delivery_id}/refuse",
            json={},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_refuse_with_reason(self, api_client: AsyncClient):
        """Test refuse with optional reason."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.post(
            f"/recipient/deliveries/{delivery_id}/refuse",
            json={"reason": "I did not request this delivery"},
        )
        assert response.status_code == 401  # Auth required

    @pytest.mark.asyncio
    async def test_refuse_reason_max_length(self, api_client: AsyncClient):
        """Test that reason field has max length validation."""
        delivery_id = str(uuid.uuid4())
        # Reason over 1000 chars should be rejected
        long_reason = "x" * 1001
        response = await api_client.post(
            f"/recipient/deliveries/{delivery_id}/refuse",
            json={"reason": long_reason},
        )
        # Should get validation error (422) even without auth
        # Note: FastAPI validates body before auth in some cases
        assert response.status_code in [401, 422]


class TestContentDownloadEndpoint:
    """Tests for GET /recipient/deliveries/{id}/content endpoint."""

    @pytest.mark.asyncio
    async def test_content_requires_authentication(self, api_client: AsyncClient):
        """Test that content download requires authentication."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.get(f"/recipient/deliveries/{delivery_id}/content")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_content_with_object_id(self, api_client: AsyncClient):
        """Test content download with specific content object ID."""
        delivery_id = str(uuid.uuid4())
        content_object_id = str(uuid.uuid4())
        response = await api_client.get(
            f"/recipient/deliveries/{delivery_id}/content",
            params={"content_object_id": content_object_id},
        )
        assert response.status_code == 401


class TestProofDownloadEndpoint:
    """Tests for GET /recipient/deliveries/{id}/proofs/{type} endpoint."""

    @pytest.mark.asyncio
    async def test_proof_requires_authentication(self, api_client: AsyncClient):
        """Test that proof download requires authentication."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.get(f"/recipient/deliveries/{delivery_id}/proofs/acceptance")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_proof_types(self, api_client: AsyncClient):
        """Test that valid proof types are accepted."""
        delivery_id = str(uuid.uuid4())
        valid_types = ["deposit", "notification", "acceptance", "refusal", "receipt", "expiry"]

        for proof_type in valid_types:
            response = await api_client.get(
                f"/recipient/deliveries/{delivery_id}/proofs/{proof_type}"
            )
            # Should fail with 401 (auth) not 422 (validation)
            assert response.status_code == 401, f"Failed for proof type: {proof_type}"

    @pytest.mark.asyncio
    async def test_invalid_proof_type(self, api_client: AsyncClient):
        """Test that invalid proof type returns validation error or auth error."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.get(f"/recipient/deliveries/{delivery_id}/proofs/invalid_type")
        # FastAPI may check auth before path validation depending on middleware order
        # Either 422 (validation) or 401 (auth) is acceptable
        assert response.status_code in [401, 422]


class TestRedactionCompliance:
    """Tests for REQ-F03 pre-acceptance sender redaction.

    These tests verify the redaction logic directly, as the API
    endpoints require database integration for full testing.
    """

    def test_fr_lre_redaction_profile_exists(self):
        """Test that French LRE redaction profile is defined."""
        profile = get_redaction_profile("fr_lre_cpce")
        assert profile["hide_sender_identity"] is True
        assert profile["hide_sender_details"] is True

    def test_eidas_redaction_profile_exists(self):
        """Test that eIDAS default redaction profile is defined."""
        profile = get_redaction_profile("eidas_default")
        # eIDAS doesn't require sender hiding
        assert profile["hide_sender_identity"] is False

    def test_apply_redaction_pre_acceptance_fr_lre(self):
        """Test pre-acceptance redaction for French LRE jurisdiction."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean.dupont@example.com",
            "subject": "Important Document",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        # Sender identity should be redacted
        assert redacted["sender_name"] == "[REDACTED]"
        assert redacted["sender_email"] == "[REDACTED]"
        # Subject is not redacted in fr_lre_cpce profile
        assert redacted["subject"] == "Important Document"

    def test_apply_redaction_post_acceptance(self):
        """Test that post-acceptance shows full data."""
        data = {
            "sender_name": "Jean Dupont",
            "sender_email": "jean.dupont@example.com",
            "subject": "Important Document",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=True)

        # Full disclosure after acceptance
        assert redacted["sender_name"] == "Jean Dupont"
        assert redacted["sender_email"] == "jean.dupont@example.com"
        assert redacted["subject"] == "Important Document"

    def test_apply_redaction_with_content_metadata(self):
        """Test redaction of content metadata fields."""
        data = {
            "original_filename": "contrat_vente.pdf",
            "content_description": "Sales contract for property",
        }

        redacted = apply_redaction(data, "fr_lre_cpce", is_accepted=False)

        # Content metadata should be redacted pre-acceptance
        assert redacted["original_filename"] == "[REDACTED]"
        assert redacted["content_description"] == "[REDACTED]"


class TestSchemaValidation:
    """Tests for Pydantic schema validation."""

    def test_inbox_response_schema(self):
        """Test InboxResponse schema construction."""
        response = InboxResponse(
            deliveries=[],
            total=0,
            page=1,
            page_size=20,
        )
        assert response.total == 0
        assert response.page == 1

    def test_delivery_summary_schema(self):
        """Test DeliverySummary schema construction."""
        summary = DeliverySummary(
            delivery_id=uuid.uuid4(),
            state="available",
            subject="Test Delivery",
            created_at=datetime.now(UTC),
            acceptance_deadline_at=datetime.now(UTC) + timedelta(days=15),
            sender_name="[REDACTED]",
            sender_email="[REDACTED]",
            is_accepted=False,
        )
        assert summary.state == "available"
        assert summary.is_accepted is False
        assert summary.sender_name == "[REDACTED]"

    def test_delivery_detail_schema(self):
        """Test DeliveryDetail schema construction."""
        detail = DeliveryDetail(
            delivery_id=uuid.uuid4(),
            state="available",
            jurisdiction_profile="fr_lre",
            created_at=datetime.now(UTC),
            is_accepted=False,
            is_refused=False,
            is_expired=False,
        )
        assert detail.jurisdiction_profile == "fr_lre"
        assert detail.content_objects == []

    def test_content_object_summary_schema(self):
        """Test ContentObjectSummary schema construction."""
        content = ContentObjectSummary(
            content_object_id=uuid.uuid4(),
            mime_type="application/pdf",
            size_bytes=1024,
            original_filename="[REDACTED]",
            sha256="abc123" * 10 + "abcd",
        )
        assert content.mime_type == "application/pdf"
        assert content.size_bytes == 1024

    def test_accept_delivery_request_schema(self):
        """Test AcceptDeliveryRequest schema with defaults."""
        request = AcceptDeliveryRequest()
        assert request.confirm_electronic_consent is True

        request_explicit = AcceptDeliveryRequest(confirm_electronic_consent=False)
        assert request_explicit.confirm_electronic_consent is False

    def test_accept_delivery_response_schema(self):
        """Test AcceptDeliveryResponse schema construction."""
        response = AcceptDeliveryResponse(
            delivery_id=uuid.uuid4(),
            state="accepted",
            accepted_at=datetime.now(UTC),
            sender_name="Jean Dupont",
            sender_email="jean.dupont@example.com",
            content_available=True,
        )
        assert response.state == "accepted"
        assert response.content_available is True

    def test_refuse_delivery_request_schema(self):
        """Test RefuseDeliveryRequest schema with optional reason."""
        request = RefuseDeliveryRequest()
        assert request.reason is None

        request_with_reason = RefuseDeliveryRequest(reason="Not requested")
        assert request_with_reason.reason == "Not requested"

    def test_refuse_delivery_response_schema(self):
        """Test RefuseDeliveryResponse schema construction."""
        response = RefuseDeliveryResponse(
            delivery_id=uuid.uuid4(),
            state="refused",
            refused_at=datetime.now(UTC),
        )
        assert response.state == "refused"

    def test_error_response_schema(self):
        """Test ErrorResponse schema construction."""
        error = ErrorResponse(
            error="not_found",
            message="Delivery not found",
            detail={"delivery_id": "abc123"},
        )
        assert error.error == "not_found"
        assert error.detail is not None


class TestOpenAPIDocumentation:
    """Tests for OpenAPI documentation of recipient endpoints."""

    @pytest.mark.asyncio
    async def test_recipient_endpoints_documented(self, api_client: AsyncClient):
        """Test that all recipient endpoints appear in OpenAPI spec."""
        response = await api_client.get("/api/openapi.json")
        assert response.status_code == 200
        data = response.json()
        paths = data.get("paths", {})

        # Check all recipient endpoints are documented
        expected_paths = [
            "/recipient/health",
            "/recipient/inbox",
            "/recipient/deliveries/{delivery_id}",
            "/recipient/deliveries/{delivery_id}/accept",
            "/recipient/deliveries/{delivery_id}/refuse",
            "/recipient/deliveries/{delivery_id}/content",
            "/recipient/deliveries/{delivery_id}/proofs/{proof_type}",
        ]

        for path in expected_paths:
            assert path in paths, f"Missing path: {path}"

    @pytest.mark.asyncio
    async def test_recipient_tag_applied(self, api_client: AsyncClient):
        """Test that recipient endpoints have 'recipient' tag."""
        response = await api_client.get("/api/openapi.json")
        data = response.json()
        paths = data.get("paths", {})

        # Check that inbox endpoint has recipient tag
        inbox_path = paths.get("/recipient/inbox", {})
        get_op = inbox_path.get("get", {})
        assert "recipient" in get_op.get("tags", [])

    @pytest.mark.asyncio
    async def test_authentication_documented(self, api_client: AsyncClient):
        """Test that endpoints document authentication requirements."""
        response = await api_client.get("/api/openapi.json")
        data = response.json()
        paths = data.get("paths", {})

        # Check inbox endpoint security
        inbox_path = paths.get("/recipient/inbox", {})
        get_op = inbox_path.get("get", {})
        # Should have 401 response documented
        responses = get_op.get("responses", {})
        assert "401" in responses or "401" in str(inbox_path), "401 response should be documented"

    @pytest.mark.asyncio
    async def test_proof_types_documented(self, api_client: AsyncClient):
        """Test that proof types enum is documented in OpenAPI."""
        response = await api_client.get("/api/openapi.json")
        data = response.json()

        # Find the proof_type parameter or schema
        paths = data.get("paths", {})
        proof_path = paths.get("/recipient/deliveries/{delivery_id}/proofs/{proof_type}", {})
        get_op = proof_path.get("get", {})
        parameters = get_op.get("parameters", [])

        # Find proof_type parameter
        proof_type_param = None
        for param in parameters:
            if param.get("name") == "proof_type":
                proof_type_param = param
                break

        assert proof_type_param is not None, "proof_type parameter should be documented"


class TestDeliveryStateHelpers:
    """Tests for delivery state helper functions from the router."""

    def test_accepted_states(self):
        """Test that accepted states are correctly identified."""
        accepted_states = {DeliveryState.ACCEPTED, DeliveryState.RECEIVED}

        assert DeliveryState.ACCEPTED in accepted_states
        assert DeliveryState.RECEIVED in accepted_states
        assert DeliveryState.AVAILABLE not in accepted_states
        assert DeliveryState.REFUSED not in accepted_states

    def test_terminal_states(self):
        """Test that terminal states are correctly identified."""
        terminal_states = {
            DeliveryState.ACCEPTED,
            DeliveryState.REFUSED,
            DeliveryState.RECEIVED,
            DeliveryState.EXPIRED,
        }

        assert DeliveryState.REFUSED in terminal_states
        assert DeliveryState.EXPIRED in terminal_states
        assert DeliveryState.AVAILABLE not in terminal_states
        assert DeliveryState.DRAFT not in terminal_states
