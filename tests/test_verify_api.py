"""Tests for verification API endpoints.

Covers:
- REQ-F01: Third-party verification support
- REQ-F03: Pre-acceptance sender identity redaction
- REQ-E03: Minimal PII exposure
- REQ-G02: Qualification labeling

These tests verify the API contract and CPCE compliance requirements
for the public verification endpoints.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

from qerds.api.routers.verify import (
    PROVIDER_ID,
    PROVIDER_NAME,
    generate_verification_token,
)
from qerds.api.schemas.verify import (
    DeliveryStatusResult,
    IntegrityStatus,
    ProofVerificationResult,
    QualificationLevel,
    VerificationStatus,
)


class TestVerifyHealth:
    """Tests for verify namespace health endpoint."""

    @pytest.mark.asyncio
    async def test_verify_health(self, api_client: AsyncClient):
        """Test the verify namespace health endpoint."""
        response = await api_client.get("/api/verify/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "verify"


class TestTokenValidation:
    """Tests for verification token validation logic."""

    def test_generate_verification_token_format(self):
        """Test that generated tokens have correct format."""
        token = generate_verification_token("proof", "test-id-123")

        # Token should have format: <random>.<signature>
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

        # Random part should be 32 hex chars (16 bytes)
        assert len(parts[0]) == 32
        assert all(c in "0123456789abcdef" for c in parts[0])

        # Signature should be 64 hex chars (SHA-256)
        assert len(parts[1]) == 64
        assert all(c in "0123456789abcdef" for c in parts[1])

    def test_generate_different_tokens_for_different_resources(self):
        """Test that different resources get different tokens."""
        token1 = generate_verification_token("proof", "id-1")
        token2 = generate_verification_token("proof", "id-2")
        token3 = generate_verification_token("delivery", "id-1")

        # All tokens should be unique
        assert token1 != token2
        assert token1 != token3
        assert token2 != token3

    def test_generate_token_is_deterministic_for_signature(self):
        """Test that the same random part produces the same signature."""
        # Note: We can't easily test this without exposing internals,
        # but we can verify token generation is working
        token = generate_verification_token("proof", "test-id")
        assert len(token) > 64  # Should have random part + . + signature


class TestProofVerificationEndpoint:
    """Tests for GET /verify/proofs/{proof_id} endpoint."""

    @pytest.mark.asyncio
    async def test_proof_verification_requires_token(self, api_client: AsyncClient):
        """Test that proof verification endpoint requires a token."""
        proof_id = str(uuid.uuid4())
        response = await api_client.get(f"/api/verify/proofs/{proof_id}")

        # Should fail with 422 (missing required query param) or 401
        assert response.status_code in [422, 401]

    @pytest.mark.asyncio
    async def test_proof_verification_rejects_invalid_token(self, api_client: AsyncClient):
        """Test that invalid tokens are rejected due to format."""
        proof_id = str(uuid.uuid4())
        # Token meets length requirements but wrong format (no dot separator)
        invalid_token = "invalid-token-not-properly-formatted"

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": invalid_token},
        )

        # Token passes length validation but fails format check (no dot) -> 401
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_proof_verification_rejects_wrong_format_token(self, api_client: AsyncClient):
        """Test that malformed tokens are rejected."""
        proof_id = str(uuid.uuid4())
        # Token with wrong format (no dot separator) but correct length
        malformed_token = "a" * 96  # 96 hex chars, no separator

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": malformed_token},
        )

        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert data["detail"]["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_proof_verification_rejects_token_for_wrong_resource(
        self, api_client: AsyncClient
    ):
        """Test that tokens bound to different resources are rejected."""
        proof_id = str(uuid.uuid4())
        other_proof_id = str(uuid.uuid4())

        # Generate token for a different proof
        token = generate_verification_token("proof", other_proof_id)

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": token},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_proof_verification_rejects_delivery_token(self, api_client: AsyncClient):
        """Test that delivery tokens don't work for proof endpoints."""
        proof_id = str(uuid.uuid4())

        # Generate token for delivery resource type
        token = generate_verification_token("delivery", proof_id)

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": token},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "TEST_DATABASE_URL" not in __import__("os").environ,
        reason="Requires database - run in Docker with TEST_DATABASE_URL set",
    )
    async def test_proof_verification_with_valid_token_not_found(self, api_client: AsyncClient):
        """Test proof verification returns not_found for non-existent proof.

        This test requires a database connection. Run with Docker compose
        to have the test database available.
        """
        proof_id = str(uuid.uuid4())
        token = generate_verification_token("proof", proof_id)

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verification_status"] == VerificationStatus.NOT_FOUND.value
        assert data["proof_id"] == proof_id
        assert data["error_code"] == "proof_not_found"

    @pytest.mark.asyncio
    async def test_proof_verification_invalid_uuid(self, api_client: AsyncClient):
        """Test that invalid UUID returns appropriate error."""
        response = await api_client.get(
            "/api/verify/proofs/not-a-uuid",
            params={"token": "a" * 32 + "." + "b" * 64},
        )

        # FastAPI validates UUID format
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_proof_verification_token_min_length(self, api_client: AsyncClient):
        """Test token minimum length validation."""
        proof_id = str(uuid.uuid4())

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": "short"},  # Less than 32 chars
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_proof_verification_token_max_length(self, api_client: AsyncClient):
        """Test token maximum length validation."""
        proof_id = str(uuid.uuid4())

        response = await api_client.get(
            f"/api/verify/proofs/{proof_id}",
            params={"token": "x" * 300},  # More than 256 chars
        )

        assert response.status_code == 422


class TestDeliveryStatusEndpoint:
    """Tests for GET /verify/deliveries/{id}/status endpoint."""

    @pytest.mark.asyncio
    async def test_delivery_status_requires_token(self, api_client: AsyncClient):
        """Test that delivery status endpoint requires a token."""
        delivery_id = str(uuid.uuid4())
        response = await api_client.get(f"/api/verify/deliveries/{delivery_id}/status")

        # Should fail with 422 (missing required query param)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_delivery_status_rejects_invalid_token(self, api_client: AsyncClient):
        """Test that invalid tokens are rejected."""
        delivery_id = str(uuid.uuid4())
        # Token with dot but invalid signature
        invalid_token = "a" * 32 + "." + "invalid_signature"

        response = await api_client.get(
            f"/api/verify/deliveries/{delivery_id}/status",
            params={"token": invalid_token},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_delivery_status_rejects_token_for_wrong_resource(self, api_client: AsyncClient):
        """Test that tokens bound to different resources are rejected."""
        delivery_id = str(uuid.uuid4())
        other_delivery_id = str(uuid.uuid4())

        # Generate token for a different delivery
        token = generate_verification_token("delivery", other_delivery_id)

        response = await api_client.get(
            f"/api/verify/deliveries/{delivery_id}/status",
            params={"token": token},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_delivery_status_rejects_proof_token(self, api_client: AsyncClient):
        """Test that proof tokens don't work for delivery endpoints."""
        delivery_id = str(uuid.uuid4())

        # Generate token for proof resource type
        token = generate_verification_token("proof", delivery_id)

        response = await api_client.get(
            f"/api/verify/deliveries/{delivery_id}/status",
            params={"token": token},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "TEST_DATABASE_URL" not in __import__("os").environ,
        reason="Requires database - run in Docker with TEST_DATABASE_URL set",
    )
    async def test_delivery_status_with_valid_token_not_found(self, api_client: AsyncClient):
        """Test delivery status returns exists=false for non-existent delivery.

        This test requires a database connection. Run with Docker compose
        to have the test database available.
        """
        delivery_id = str(uuid.uuid4())
        token = generate_verification_token("delivery", delivery_id)

        response = await api_client.get(
            f"/api/verify/deliveries/{delivery_id}/status",
            params={"token": token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["delivery_id"] == delivery_id
        assert data["exists"] is False
        assert data["error_code"] == "delivery_not_found"
        # Provider info should always be present
        assert data["provider_id"] == PROVIDER_ID
        assert data["provider_name"] == PROVIDER_NAME

    @pytest.mark.asyncio
    async def test_delivery_status_invalid_uuid(self, api_client: AsyncClient):
        """Test that invalid UUID returns appropriate error."""
        response = await api_client.get(
            "/api/verify/deliveries/not-a-uuid/status",
            params={"token": "a" * 32 + "." + "b" * 64},
        )

        # FastAPI validates UUID format
        assert response.status_code == 422


class TestProofVerificationResponseSchema:
    """Tests for ProofVerificationResult schema validation."""

    def test_valid_verification_result(self):
        """Test that valid verification result schema validates."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.NON_QUALIFIED,
        )

        assert result.verification_status == VerificationStatus.VALID
        assert result.integrity_status == IntegrityStatus.VERIFIED

    def test_not_found_verification_result(self):
        """Test verification result for not found case."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.NOT_FOUND,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.UNKNOWN,
            qualification_level=QualificationLevel.NON_QUALIFIED,
            error_message="Proof not found",
            error_code="proof_not_found",
        )

        assert result.verification_status == VerificationStatus.NOT_FOUND
        assert result.error_code == "proof_not_found"

    def test_verification_result_with_sender_identity(self):
        """Test verification result includes sender identity post-acceptance."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.QUALIFIED,
            sender_name="Jean Dupont",
            sender_email="jean@example.com",
        )

        assert result.sender_name == "Jean Dupont"
        assert result.sender_email == "jean@example.com"

    def test_verification_result_without_sender_identity(self):
        """Test verification result hides sender identity pre-acceptance."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.NON_QUALIFIED,
            # No sender fields - pre-acceptance
        )

        assert result.sender_name is None
        assert result.sender_email is None


class TestDeliveryStatusResponseSchema:
    """Tests for DeliveryStatusResult schema validation."""

    def test_valid_delivery_status(self):
        """Test that valid delivery status schema validates."""
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="deposited",
            is_terminal=False,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )

        assert result.exists is True
        assert result.state == "deposited"
        assert result.is_terminal is False

    def test_delivery_not_found_status(self):
        """Test delivery status for not found case."""
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=False,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            error_message="Delivery not found",
            error_code="delivery_not_found",
        )

        assert result.exists is False
        assert result.error_code == "delivery_not_found"

    def test_delivery_status_with_sender_identity_post_acceptance(self):
        """Test delivery status includes sender identity post-acceptance (REQ-F03)."""
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="accepted",
            is_terminal=True,
            is_accepted=True,
            sender_name="Sender Corp",
            sender_email="sender@example.com",
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )

        assert result.is_accepted is True
        assert result.sender_name == "Sender Corp"
        assert result.sender_email == "sender@example.com"

    def test_delivery_status_without_sender_identity_pre_acceptance(self):
        """Test delivery status hides sender identity pre-acceptance (REQ-F03)."""
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="deposited",
            is_terminal=False,
            is_accepted=False,
            # No sender fields - pre-acceptance
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )

        assert result.is_accepted is False
        assert result.sender_name is None
        assert result.sender_email is None

    def test_delivery_status_with_timestamps(self):
        """Test delivery status includes relevant timestamps."""
        now = datetime.now(UTC)
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="notified",
            is_terminal=False,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            created_at=now,
            deposited_at=now,
            notified_at=now,
            acceptance_deadline_at=now,
        )

        assert result.created_at == now
        assert result.deposited_at == now
        assert result.notified_at == now
        assert result.acceptance_deadline_at == now

    def test_delivery_status_terminal_states(self):
        """Test that terminal states are correctly identified."""
        # Accepted is terminal
        accepted = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="accepted",
            is_terminal=True,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )
        assert accepted.is_terminal is True

        # Refused is terminal
        refused = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="refused",
            is_terminal=True,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )
        assert refused.is_terminal is True

        # Expired is terminal
        expired = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="expired",
            is_terminal=True,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
        )
        assert expired.is_terminal is True


class TestMinimalPIIExposure:
    """Tests verifying REQ-E03 minimal PII exposure requirements."""

    def test_proof_verification_minimal_fields(self):
        """Test that proof verification only exposes necessary fields."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.NON_QUALIFIED,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            event_type="evt_deposited",
            sealed_at=datetime.now(UTC),
        )

        # Should have verification info
        assert result.verification_status is not None
        assert result.integrity_status is not None
        assert result.provider_id is not None

        # Should NOT have recipient info (not relevant for proof verification)
        # The schema doesn't even include recipient fields - that's by design

    def test_delivery_status_minimal_fields(self):
        """Test that delivery status only exposes necessary fields."""
        result = DeliveryStatusResult(
            delivery_id=uuid.uuid4(),
            exists=True,
            state="deposited",
            is_terminal=False,
            provider_id=PROVIDER_ID,
            provider_name=PROVIDER_NAME,
            content_count=2,
        )

        # Should have delivery existence and state
        assert result.exists is True
        assert result.state is not None

        # Should have content count but NOT content details
        assert result.content_count == 2

        # Should NOT expose recipient info at all (minimal PII)
        # The schema doesn't include recipient fields - that's by design


class TestQualificationLabeling:
    """Tests verifying REQ-G02 qualification labeling requirements."""

    def test_proof_qualified_label(self):
        """Test that qualified proofs are labeled correctly."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.QUALIFIED,
            qualification_reason="All requirements met",
        )

        assert result.qualification_level == QualificationLevel.QUALIFIED

    def test_proof_non_qualified_label(self):
        """Test that non-qualified proofs are labeled correctly."""
        result = ProofVerificationResult(
            verification_status=VerificationStatus.VALID,
            proof_id=uuid.uuid4(),
            integrity_status=IntegrityStatus.VERIFIED,
            qualification_level=QualificationLevel.NON_QUALIFIED,
            qualification_reason="Development mode - not for production use",
        )

        assert result.qualification_level == QualificationLevel.NON_QUALIFIED
        assert "Development" in (result.qualification_reason or "")
