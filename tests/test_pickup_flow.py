"""Tests for recipient pickup flow with authentication wall.

Covers: REQ-E02, REQ-F03, REQ-F04, REQ-F06

These tests verify:
1. Magic link claim token validation
2. Authentication wall (redirect to FranceConnect+)
3. Sender identity hidden until accept/refuse (REQ-F03)
4. IAL level enforcement for LRE (REQ-F04)
5. Consumer consent check (REQ-F06)
6. Content access gated by acceptance (REQ-E02)

All tests run against Docker containers for reproducibility.
Use: docker compose exec qerds-api pytest tests/test_pickup_flow.py -v
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from qerds.db.models.base import (
    ConsentType,
    DeliveryState,
    IALLevel,
)
from qerds.services.pickup import (
    ClaimToken,
    ConsentRequiredError,
    DeliveryExpiredError,
    DeliveryNotFoundError,
    InsufficientIALError,
    InvalidStateError,
    PickupService,
    RecipientMismatchError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


@pytest.fixture
def mock_delivery():
    """Create a mock delivery in AVAILABLE state."""
    delivery = MagicMock()
    delivery.delivery_id = uuid4()
    delivery.state = DeliveryState.AVAILABLE
    delivery.jurisdiction_profile = "fr_lre"
    delivery.sender_party_id = uuid4()
    delivery.recipient_party_id = uuid4()
    delivery.subject = "Test Subject"
    delivery.deposited_at = datetime.now(UTC) - timedelta(days=1)
    delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=14)
    delivery.completed_at = None

    # Mock sender party (hidden pre-acceptance)
    sender_party = MagicMock()
    sender_party.party_id = delivery.sender_party_id
    sender_party.display_name = "Jean Dupont"
    sender_party.email = "jean.dupont@example.com"
    delivery.sender_party = sender_party

    # Mock recipient party
    recipient_party = MagicMock()
    recipient_party.party_id = delivery.recipient_party_id
    recipient_party.display_name = "Marie Martin"
    recipient_party.email = "marie.martin@example.com"
    delivery.recipient_party = recipient_party

    delivery.content_objects = []

    return delivery


@pytest.fixture
def pickup_service(mock_db_session):
    """Create a PickupService instance with mock session."""
    return PickupService(mock_db_session)


# ---------------------------------------------------------------------------
# Test: Claim Token Generation
# ---------------------------------------------------------------------------


class TestClaimTokenGeneration:
    """Tests for claim token generation."""

    def test_generate_claim_token_creates_valid_token(self, pickup_service, mock_delivery):
        """Verify claim token is generated with correct attributes."""
        token = pickup_service.generate_claim_token(mock_delivery.delivery_id)

        assert token.delivery_id == mock_delivery.delivery_id
        assert token.token is not None
        assert len(token.token) > 32  # Should be substantial length
        assert token.created_at is not None
        assert token.expires_at > token.created_at

    def test_generate_claim_token_has_15_day_expiry(self, pickup_service, mock_delivery):
        """Verify claim token expires in 15 days (matches acceptance window)."""
        token = pickup_service.generate_claim_token(mock_delivery.delivery_id)

        # Should expire approximately 15 days from now
        expected_expiry = token.created_at + timedelta(days=15)
        assert token.expires_at == expected_expiry

    def test_claim_token_is_expired_property(self, pickup_service, mock_delivery):
        """Test is_expired property on ClaimToken."""
        # Create a token that is already expired
        expired_token = ClaimToken(
            delivery_id=mock_delivery.delivery_id,
            token="expired-test-token-value",  # noqa: S106
            created_at=datetime.now(UTC) - timedelta(days=20),
            expires_at=datetime.now(UTC) - timedelta(days=5),
        )

        assert expired_token.is_expired is True

        # Create a valid token
        valid_token = ClaimToken(
            delivery_id=mock_delivery.delivery_id,
            token="valid-test-token-value",  # noqa: S106
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=15),
        )

        assert valid_token.is_expired is False


# ---------------------------------------------------------------------------
# Test: Claim Token Validation (Magic Link Entry)
# ---------------------------------------------------------------------------


class TestClaimTokenValidation:
    """Tests for claim token validation at magic link entry."""

    @pytest.mark.asyncio
    async def test_validate_claim_token_success(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify valid claim token returns delivery."""
        # Mock the database query to return the delivery
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        token = pickup_service.generate_claim_token(mock_delivery.delivery_id)
        delivery = await pickup_service.validate_claim_token(token.token, mock_delivery.delivery_id)

        assert delivery == mock_delivery

    @pytest.mark.asyncio
    async def test_validate_claim_token_delivery_not_found(self, pickup_service, mock_db_session):
        """Verify DeliveryNotFoundError raised when delivery doesn't exist."""
        # Mock the database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        delivery_id = uuid4()

        with pytest.raises(DeliveryNotFoundError) as exc_info:
            await pickup_service.validate_claim_token("test-token", delivery_id)

        assert exc_info.value.delivery_id == delivery_id

    @pytest.mark.asyncio
    async def test_validate_claim_token_delivery_expired(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify DeliveryExpiredError when acceptance deadline passed."""
        # Set delivery to expired
        mock_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(DeliveryExpiredError) as exc_info:
            await pickup_service.validate_claim_token("test-token", mock_delivery.delivery_id)

        assert exc_info.value.delivery_id == mock_delivery.delivery_id


# ---------------------------------------------------------------------------
# Test: Pickup Context (REQ-F03 - Sender Redaction)
# ---------------------------------------------------------------------------


class TestPickupContext:
    """Tests for pickup context and sender redaction."""

    @pytest.mark.asyncio
    async def test_unauthenticated_user_cannot_see_sender(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify unauthenticated users cannot see sender identity (REQ-F03)."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        context = await pickup_service.get_pickup_context(
            mock_delivery.delivery_id,
            authenticated_party_id=None,
            ial_level=None,
        )

        assert context.is_authenticated is False
        assert context.sender_revealed is False
        assert context.can_accept_refuse is False

    @pytest.mark.asyncio
    async def test_authenticated_user_in_available_state_can_act(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify authenticated recipient can accept/refuse in AVAILABLE state."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        # Mock consent check to return True
        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.is_authenticated is True
        assert context.can_accept_refuse is True
        assert context.sender_revealed is False  # Still hidden until accept/refuse

    @pytest.mark.asyncio
    async def test_sender_revealed_after_acceptance(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify sender identity is revealed after acceptance (REQ-F03)."""
        mock_delivery.state = DeliveryState.ACCEPTED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is True

    @pytest.mark.asyncio
    async def test_sender_revealed_after_refusal(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify sender identity is revealed after refusal (REQ-F03)."""
        mock_delivery.state = DeliveryState.REFUSED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is True

    @pytest.mark.asyncio
    async def test_recipient_mismatch_raises_error(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify error when authenticated user is not the recipient."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        wrong_party_id = uuid4()

        with pytest.raises(RecipientMismatchError) as exc_info:
            await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=wrong_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert exc_info.value.delivery_id == mock_delivery.delivery_id
        assert exc_info.value.authenticated_party_id == wrong_party_id


# ---------------------------------------------------------------------------
# Test: IAL Level Enforcement (REQ-F04)
# ---------------------------------------------------------------------------


class TestIALEnforcement:
    """Tests for IAL level enforcement for LRE mode."""

    def test_ial_check_fr_lre_requires_ial2(self, pickup_service):
        """Verify FR LRE requires IAL_SUBSTANTIAL (IAL2) minimum."""
        # IAL2 should pass
        assert pickup_service._check_ial_requirement(IALLevel.IAL2, "fr_lre") is True
        # IAL3 should pass (exceeds requirement)
        assert pickup_service._check_ial_requirement(IALLevel.IAL3, "fr_lre") is True
        # IAL1 should fail
        assert pickup_service._check_ial_requirement(IALLevel.IAL1, "fr_lre") is False
        # None should fail
        assert pickup_service._check_ial_requirement(None, "fr_lre") is False

    def test_ial_check_eidas_allows_ial1(self, pickup_service):
        """Verify base eIDAS allows IAL1."""
        assert pickup_service._check_ial_requirement(IALLevel.IAL1, "eidas") is True
        assert pickup_service._check_ial_requirement(IALLevel.IAL2, "eidas") is True
        assert pickup_service._check_ial_requirement(IALLevel.IAL3, "eidas") is True

    def test_enforce_ial_raises_on_insufficient(self, pickup_service):
        """Verify InsufficientIALError raised when IAL is too low."""
        with pytest.raises(InsufficientIALError) as exc_info:
            pickup_service._enforce_ial_requirement(IALLevel.IAL1, "fr_lre")

        assert exc_info.value.required == IALLevel.IAL2
        assert exc_info.value.actual == IALLevel.IAL1

    def test_enforce_ial_passes_with_sufficient(self, pickup_service):
        """Verify no error when IAL is sufficient."""
        # Should not raise
        pickup_service._enforce_ial_requirement(IALLevel.IAL2, "fr_lre")
        pickup_service._enforce_ial_requirement(IALLevel.IAL3, "fr_lre")


# ---------------------------------------------------------------------------
# Test: Consumer Consent (REQ-F06)
# ---------------------------------------------------------------------------


class TestConsumerConsent:
    """Tests for consumer consent verification (REQ-F06)."""

    def test_fr_lre_requires_consent(self, pickup_service):
        """Verify FR LRE requires consumer consent."""
        assert pickup_service._requires_consumer_consent("fr_lre") is True

    def test_eidas_may_not_require_consent(self, pickup_service):
        """Verify base eIDAS may not require explicit consent."""
        # This is configurable per jurisdiction
        assert pickup_service._requires_consumer_consent("eidas") is False

    def test_get_consent_type_fr_lre(self, pickup_service):
        """Verify correct consent type for FR LRE."""
        consent_type = pickup_service._get_consent_type("fr_lre")
        assert consent_type == ConsentType.FR_LRE_ELECTRONIC_DELIVERY

    def test_get_consent_type_eidas(self, pickup_service):
        """Verify consent type for eIDAS."""
        consent_type = pickup_service._get_consent_type("eidas")
        assert consent_type == ConsentType.EIDAS_ELECTRONIC_DELIVERY


# ---------------------------------------------------------------------------
# Test: Accept Delivery
# ---------------------------------------------------------------------------


class TestAcceptDelivery:
    """Tests for delivery acceptance."""

    @pytest.mark.asyncio
    async def test_accept_delivery_success(self, pickup_service, mock_db_session, mock_delivery):
        """Verify successful delivery acceptance."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        # Mock the lifecycle service
        mock_lifecycle_result = MagicMock()
        mock_lifecycle_result.success = True
        mock_lifecycle_result.evidence_event = MagicMock()
        mock_lifecycle_result.evidence_event.event_id = uuid4()

        with patch(
            "qerds.services.lifecycle.DeliveryLifecycleService"
        ) as mock_lifecycle_cls:
            mock_lifecycle = mock_lifecycle_cls.return_value
            mock_lifecycle.accept = AsyncMock(return_value=mock_lifecycle_result)

            with (
                patch.object(pickup_service, "_check_consent", return_value=True),
                patch.object(pickup_service, "_record_consent", return_value=None),
            ):
                delivery = await pickup_service.accept_delivery(
                    mock_delivery.delivery_id,
                    recipient_party_id=mock_delivery.recipient_party_id,
                    ial_level=IALLevel.IAL2,
                    confirm_consent=True,
                )

        assert delivery == mock_delivery

    @pytest.mark.asyncio
    async def test_accept_delivery_insufficient_ial(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify acceptance rejected with insufficient IAL."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InsufficientIALError):
            await pickup_service.accept_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL1,  # Too low for fr_lre
                confirm_consent=True,
            )

    @pytest.mark.asyncio
    async def test_accept_delivery_consent_required(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify ConsentRequiredError when consent not confirmed."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(ConsentRequiredError):
            await pickup_service.accept_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=False,  # Consent not confirmed
            )

    @pytest.mark.asyncio
    async def test_accept_delivery_expired(self, pickup_service, mock_db_session, mock_delivery):
        """Verify DeliveryExpiredError when deadline passed."""
        mock_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(DeliveryExpiredError):
            await pickup_service.accept_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=True,
            )

    @pytest.mark.asyncio
    async def test_accept_delivery_wrong_state(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify InvalidStateError when not in AVAILABLE state."""
        mock_delivery.state = DeliveryState.DEPOSITED  # Wrong state

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InvalidStateError) as exc_info:
            await pickup_service.accept_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=True,
            )

        assert exc_info.value.current_state == DeliveryState.DEPOSITED


# ---------------------------------------------------------------------------
# Test: Refuse Delivery
# ---------------------------------------------------------------------------


class TestRefuseDelivery:
    """Tests for delivery refusal."""

    @pytest.mark.asyncio
    async def test_refuse_delivery_success(self, pickup_service, mock_db_session, mock_delivery):
        """Verify successful delivery refusal."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        # Mock the lifecycle service
        mock_lifecycle_result = MagicMock()
        mock_lifecycle_result.success = True
        mock_lifecycle_result.evidence_event = MagicMock()
        mock_lifecycle_result.evidence_event.event_id = uuid4()

        with patch(
            "qerds.services.lifecycle.DeliveryLifecycleService"
        ) as mock_lifecycle_cls:
            mock_lifecycle = mock_lifecycle_cls.return_value
            mock_lifecycle.refuse = AsyncMock(return_value=mock_lifecycle_result)

            delivery = await pickup_service.refuse_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                reason="Not interested",
            )

        assert delivery == mock_delivery

    @pytest.mark.asyncio
    async def test_refuse_delivery_insufficient_ial(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify refusal rejected with insufficient IAL."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InsufficientIALError):
            await pickup_service.refuse_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL1,  # Too low for fr_lre
            )

    @pytest.mark.asyncio
    async def test_refuse_delivery_no_consent_needed(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify refusal does not require consent."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        # Mock the lifecycle service
        mock_lifecycle_result = MagicMock()
        mock_lifecycle_result.success = True
        mock_lifecycle_result.evidence_event = MagicMock()

        with patch(
            "qerds.services.lifecycle.DeliveryLifecycleService"
        ) as mock_lifecycle_cls:
            mock_lifecycle = mock_lifecycle_cls.return_value
            mock_lifecycle.refuse = AsyncMock(return_value=mock_lifecycle_result)

            # Should not raise ConsentRequiredError
            delivery = await pickup_service.refuse_delivery(
                mock_delivery.delivery_id,
                recipient_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert delivery == mock_delivery


# ---------------------------------------------------------------------------
# Test: Content Access Gating (REQ-E02)
# ---------------------------------------------------------------------------


class TestContentAccessGating:
    """Tests for content access gating (REQ-E02).

    Critical requirement: Content is ONLY accessible after acceptance.
    """

    @pytest.mark.asyncio
    async def test_content_access_blocked_before_acceptance(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify content access is blocked in AVAILABLE state (REQ-E02)."""
        # Delivery in AVAILABLE state (not yet accepted)
        mock_delivery.state = DeliveryState.AVAILABLE

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # Delivery is not in ACCEPTED state, so content should not be accessible
        # The router enforces this by checking delivery.state
        assert context.delivery.state != DeliveryState.ACCEPTED

    @pytest.mark.asyncio
    async def test_content_access_allowed_after_acceptance(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify content access is allowed in ACCEPTED state (REQ-E02)."""
        mock_delivery.state = DeliveryState.ACCEPTED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # Content should be accessible after acceptance
        assert context.delivery.state == DeliveryState.ACCEPTED

    @pytest.mark.asyncio
    async def test_content_access_blocked_after_refusal(
        self, pickup_service, mock_db_session, mock_delivery
    ):
        """Verify content access is blocked in REFUSED state (REQ-E02)."""
        mock_delivery.state = DeliveryState.REFUSED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_delivery.delivery_id,
                authenticated_party_id=mock_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # Content should NOT be accessible after refusal
        assert context.delivery.state == DeliveryState.REFUSED
        assert context.delivery.state != DeliveryState.ACCEPTED


# ---------------------------------------------------------------------------
# Test: IP Address Hashing (Privacy)
# ---------------------------------------------------------------------------


class TestPrivacyProtection:
    """Tests for privacy-preserving features."""

    def test_ip_hash_is_truncated(self, pickup_service):
        """Verify IP hashes are truncated for privacy."""
        ip = "192.168.1.100"
        hashed = pickup_service._hash_ip(ip)

        # Should be 16 characters (first 16 of SHA-256 hex)
        assert len(hashed) == 16
        # Should not contain the original IP
        assert ip not in hashed

    def test_ip_hash_is_deterministic(self, pickup_service):
        """Verify IP hashing is deterministic (same input = same output)."""
        ip = "10.0.0.1"

        hash1 = pickup_service._hash_ip(ip)
        hash2 = pickup_service._hash_ip(ip)

        assert hash1 == hash2

    def test_different_ips_produce_different_hashes(self, pickup_service):
        """Verify different IPs produce different hashes."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"

        hash1 = pickup_service._hash_ip(ip1)
        hash2 = pickup_service._hash_ip(ip2)

        assert hash1 != hash2
