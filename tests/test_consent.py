"""Tests for consumer consent management (REQ-F06).

Tests cover:
- Consent state machine (PENDING -> GRANTED -> WITHDRAWN)
- Consent grant with audit trail
- Consent withdrawal with audit trail
- Delivery workflow consent verification
- Evidence export for compliance
- API endpoint behavior
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import ConsentState, ConsentType
from qerds.services.consent import (
    ConsentAlreadyGrantedError,
    ConsentEvidence,
    ConsentNotFoundError,
    ConsentRecord,
    ConsentRequiredError,
    ConsentService,
    InvalidConsentStateError,
)

# =============================================================================
# Test Fixtures
# =============================================================================


def create_mock_consent(
    consent_id=None,
    recipient_party_id=None,
    consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
    state=ConsentState.PENDING,
    consented_at=None,
    consented_by=None,
    withdrawn_at=None,
):
    """Create a mock RecipientConsent object."""
    consent = MagicMock()
    consent.consent_id = consent_id or uuid4()
    consent.recipient_party_id = recipient_party_id or uuid4()
    consent.consent_type = consent_type
    consent.state = state
    consent.consented_at = consented_at
    consent.consented_by = consented_by
    consent.withdrawn_at = withdrawn_at
    consent.created_at = datetime.now(UTC)
    consent.updated_at = datetime.now(UTC)
    consent.consent_ip_address = None
    consent.consent_user_agent = None
    consent.consent_evidence_object_ref = None
    consent.withdrawal_reason = None
    consent.withdrawal_ip_address = None
    consent.withdrawal_user_agent = None
    consent.withdrawal_evidence_object_ref = None
    consent.consent_metadata = None
    return consent


def create_mock_session(consent=None):
    """Create a mock SQLAlchemy async session.

    Args:
        consent: Consent to return from queries, or None.

    Returns:
        Mock async session.
    """
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        result.scalar_one_or_none.return_value = consent
        scalars_result = MagicMock()
        scalars_result.all.return_value = [consent] if consent else []
        result.scalars.return_value = scalars_result
        return result

    session.execute = mock_execute
    session.add = MagicMock()
    session.flush = AsyncMock()

    return session


# =============================================================================
# Test ConsentState Enum
# =============================================================================


class TestConsentState:
    """Tests for ConsentState enum values."""

    def test_pending_state_exists(self):
        """PENDING state is defined."""
        assert ConsentState.PENDING.value == "pending"

    def test_granted_state_exists(self):
        """GRANTED state is defined."""
        assert ConsentState.GRANTED.value == "granted"

    def test_withdrawn_state_exists(self):
        """WITHDRAWN state is defined."""
        assert ConsentState.WITHDRAWN.value == "withdrawn"


# =============================================================================
# Test ConsentService - State Checks
# =============================================================================


class TestConsentStateChecks:
    """Tests for consent state checking methods."""

    @pytest.mark.asyncio
    async def test_has_valid_consent_returns_true_when_granted(self):
        """has_valid_consent returns True when consent is GRANTED."""
        consent = create_mock_consent(state=ConsentState.GRANTED)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.has_valid_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_has_valid_consent_returns_false_when_pending(self):
        """has_valid_consent returns False when consent is PENDING."""
        consent = create_mock_consent(state=ConsentState.PENDING)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.has_valid_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_has_valid_consent_returns_false_when_withdrawn(self):
        """has_valid_consent returns False when consent is WITHDRAWN."""
        consent = create_mock_consent(state=ConsentState.WITHDRAWN)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.has_valid_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_has_valid_consent_returns_false_when_no_record(self):
        """has_valid_consent returns False when no consent record exists."""
        session = create_mock_session(None)

        service = ConsentService(session)
        result = await service.has_valid_consent(
            recipient_party_id=uuid4(),
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_get_consent_state_returns_pending_when_no_record(self):
        """get_consent_state returns PENDING when no record exists."""
        session = create_mock_session(None)

        service = ConsentService(session)
        state = await service.get_consent_state(
            recipient_party_id=uuid4(),
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert state == ConsentState.PENDING

    @pytest.mark.asyncio
    async def test_get_consent_state_returns_current_state(self):
        """get_consent_state returns the current state from record."""
        consent = create_mock_consent(state=ConsentState.GRANTED)
        session = create_mock_session(consent)

        service = ConsentService(session)
        state = await service.get_consent_state(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert state == ConsentState.GRANTED


# =============================================================================
# Test ConsentService - Grant Consent
# =============================================================================


class TestGrantConsent:
    """Tests for consent grant functionality."""

    @pytest.mark.asyncio
    async def test_grant_consent_from_pending(self):
        """grant_consent transitions from PENDING to GRANTED."""
        recipient_id = uuid4()
        consent = create_mock_consent(
            recipient_party_id=recipient_id,
            state=ConsentState.PENDING,
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.grant_consent(
            recipient_party_id=recipient_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            consented_by=recipient_id,
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
        )

        assert result.state == ConsentState.GRANTED
        assert result.consented_at is not None
        assert result.consented_by == recipient_id
        assert result.consent_ip_address == "192.168.1.1"
        assert result.consent_user_agent == "TestBrowser/1.0"

    @pytest.mark.asyncio
    async def test_grant_consent_from_withdrawn(self):
        """grant_consent transitions from WITHDRAWN to GRANTED (re-grant)."""
        recipient_id = uuid4()
        consent = create_mock_consent(
            recipient_party_id=recipient_id,
            state=ConsentState.WITHDRAWN,
            withdrawn_at=datetime.now(UTC) - timedelta(days=1),
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.grant_consent(
            recipient_party_id=recipient_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result.state == ConsentState.GRANTED

    @pytest.mark.asyncio
    async def test_grant_consent_raises_when_already_granted(self):
        """grant_consent raises ConsentAlreadyGrantedError if already GRANTED."""
        consent = create_mock_consent(state=ConsentState.GRANTED)
        session = create_mock_session(consent)

        service = ConsentService(session)

        with pytest.raises(ConsentAlreadyGrantedError) as exc:
            await service.grant_consent(
                recipient_party_id=consent.recipient_party_id,
                consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            )

        assert exc.value.consent_id == consent.consent_id

    @pytest.mark.asyncio
    async def test_grant_consent_stores_consent_text_hash(self):
        """grant_consent stores consent text hash in metadata."""
        consent = create_mock_consent(state=ConsentState.PENDING)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.grant_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            consent_text_hash="abc123def456",
        )

        assert result.consent_metadata is not None
        assert result.consent_metadata.get("consent_text_hash") == "abc123def456"

    @pytest.mark.asyncio
    async def test_grant_consent_creates_evidence_reference(self):
        """grant_consent creates evidence object reference."""
        consent = create_mock_consent(state=ConsentState.PENDING)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.grant_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result.consent_evidence_object_ref is not None
        assert "grant" in result.consent_evidence_object_ref


# =============================================================================
# Test ConsentService - Withdraw Consent
# =============================================================================


class TestWithdrawConsent:
    """Tests for consent withdrawal functionality."""

    @pytest.mark.asyncio
    async def test_withdraw_consent_from_granted(self):
        """withdraw_consent transitions from GRANTED to WITHDRAWN."""
        recipient_id = uuid4()
        consent = create_mock_consent(
            recipient_party_id=recipient_id,
            state=ConsentState.GRANTED,
            consented_at=datetime.now(UTC) - timedelta(days=30),
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.withdraw_consent(
            recipient_party_id=recipient_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            reason="No longer want electronic delivery",
            ip_address="192.168.1.2",
            user_agent="TestBrowser/2.0",
        )

        assert result.state == ConsentState.WITHDRAWN
        assert result.withdrawn_at is not None
        assert result.withdrawal_reason == "No longer want electronic delivery"
        assert result.withdrawal_ip_address == "192.168.1.2"
        assert result.withdrawal_user_agent == "TestBrowser/2.0"

    @pytest.mark.asyncio
    async def test_withdraw_consent_raises_when_not_found(self):
        """withdraw_consent raises ConsentNotFoundError if no record."""
        session = create_mock_session(None)

        service = ConsentService(session)

        with pytest.raises(ConsentNotFoundError) as exc:
            await service.withdraw_consent(
                recipient_party_id=uuid4(),
                consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            )

        assert "not found" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_withdraw_consent_raises_when_pending(self):
        """withdraw_consent raises InvalidConsentStateError if PENDING."""
        consent = create_mock_consent(state=ConsentState.PENDING)
        session = create_mock_session(consent)

        service = ConsentService(session)

        with pytest.raises(InvalidConsentStateError) as exc:
            await service.withdraw_consent(
                recipient_party_id=consent.recipient_party_id,
                consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            )

        assert exc.value.current_state == ConsentState.PENDING
        assert exc.value.operation == "withdraw"

    @pytest.mark.asyncio
    async def test_withdraw_consent_raises_when_already_withdrawn(self):
        """withdraw_consent raises InvalidConsentStateError if already WITHDRAWN."""
        consent = create_mock_consent(state=ConsentState.WITHDRAWN)
        session = create_mock_session(consent)

        service = ConsentService(session)

        with pytest.raises(InvalidConsentStateError) as exc:
            await service.withdraw_consent(
                recipient_party_id=consent.recipient_party_id,
                consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            )

        assert exc.value.current_state == ConsentState.WITHDRAWN

    @pytest.mark.asyncio
    async def test_withdraw_consent_creates_evidence_reference(self):
        """withdraw_consent creates withdrawal evidence reference."""
        consent = create_mock_consent(state=ConsentState.GRANTED)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.withdraw_consent(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert result.withdrawal_evidence_object_ref is not None
        assert "withdraw" in result.withdrawal_evidence_object_ref


# =============================================================================
# Test ConsentService - Delivery Verification
# =============================================================================


class TestDeliveryVerification:
    """Tests for consent verification in delivery workflow."""

    @pytest.mark.asyncio
    async def test_verify_consent_passes_when_granted(self):
        """verify_consent_for_delivery passes when consent is GRANTED."""
        consent = create_mock_consent(state=ConsentState.GRANTED)
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.verify_consent_for_delivery(
            recipient_party_id=consent.recipient_party_id,
            jurisdiction_profile="fr_lre",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_consent_raises_when_pending(self):
        """verify_consent_for_delivery raises ConsentRequiredError when PENDING."""
        consent = create_mock_consent(state=ConsentState.PENDING)
        session = create_mock_session(consent)

        service = ConsentService(session)

        with pytest.raises(ConsentRequiredError) as exc:
            await service.verify_consent_for_delivery(
                recipient_party_id=consent.recipient_party_id,
                jurisdiction_profile="fr_lre",
            )

        assert exc.value.consent_type == ConsentType.FR_LRE_ELECTRONIC_DELIVERY

    @pytest.mark.asyncio
    async def test_verify_consent_raises_when_withdrawn(self):
        """verify_consent_for_delivery raises ConsentRequiredError when WITHDRAWN."""
        consent = create_mock_consent(state=ConsentState.WITHDRAWN)
        session = create_mock_session(consent)

        service = ConsentService(session)

        with pytest.raises(ConsentRequiredError):
            await service.verify_consent_for_delivery(
                recipient_party_id=consent.recipient_party_id,
                jurisdiction_profile="fr_lre",
            )

    @pytest.mark.asyncio
    async def test_verify_consent_raises_for_unknown_jurisdiction(self):
        """verify_consent_for_delivery raises ValueError for unknown jurisdiction."""
        session = create_mock_session(None)

        service = ConsentService(session)

        with pytest.raises(ValueError, match="Unknown jurisdiction profile"):
            await service.verify_consent_for_delivery(
                recipient_party_id=uuid4(),
                jurisdiction_profile="unknown_profile",
            )

    @pytest.mark.asyncio
    async def test_verify_consent_maps_fr_lre_correctly(self):
        """verify_consent_for_delivery maps fr_lre to FR_LRE_ELECTRONIC_DELIVERY."""
        consent = create_mock_consent(
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            state=ConsentState.GRANTED,
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.verify_consent_for_delivery(
            recipient_party_id=consent.recipient_party_id,
            jurisdiction_profile="fr_lre",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_consent_maps_eidas_correctly(self):
        """verify_consent_for_delivery maps eidas to EIDAS_ELECTRONIC_DELIVERY."""
        consent = create_mock_consent(
            consent_type=ConsentType.EIDAS_ELECTRONIC_DELIVERY,
            state=ConsentState.GRANTED,
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        result = await service.verify_consent_for_delivery(
            recipient_party_id=consent.recipient_party_id,
            jurisdiction_profile="eidas",
        )

        assert result is True


# =============================================================================
# Test ConsentService - Evidence Export
# =============================================================================


class TestEvidenceExport:
    """Tests for consent evidence export functionality."""

    @pytest.mark.asyncio
    async def test_export_evidence_includes_basic_fields(self):
        """export_consent_evidence includes all basic fields."""
        consent = create_mock_consent(
            state=ConsentState.GRANTED,
            consented_at=datetime.now(UTC),
        )
        session = create_mock_session(consent)

        service = ConsentService(session)
        evidence = await service.export_consent_evidence(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert "consent_id" in evidence
        assert "recipient_party_id" in evidence
        assert "consent_type" in evidence
        assert "state" in evidence
        assert "created_at" in evidence
        assert "updated_at" in evidence

    @pytest.mark.asyncio
    async def test_export_evidence_includes_grant_evidence(self):
        """export_consent_evidence includes grant evidence when consented."""
        now = datetime.now(UTC)
        consent = create_mock_consent(
            state=ConsentState.GRANTED,
            consented_at=now,
            consented_by=uuid4(),
        )
        consent.consent_ip_address = "192.168.1.1"
        consent.consent_user_agent = "TestBrowser/1.0"
        consent.consent_evidence_object_ref = "inline:consent:test"
        session = create_mock_session(consent)

        service = ConsentService(session)
        evidence = await service.export_consent_evidence(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert evidence["grant_evidence"] is not None
        assert "consented_at" in evidence["grant_evidence"]
        assert "ip_address" in evidence["grant_evidence"]
        assert "user_agent" in evidence["grant_evidence"]
        assert "evidence_ref" in evidence["grant_evidence"]

    @pytest.mark.asyncio
    async def test_export_evidence_includes_withdrawal_evidence(self):
        """export_consent_evidence includes withdrawal evidence when withdrawn."""
        consent = create_mock_consent(
            state=ConsentState.WITHDRAWN,
            consented_at=datetime.now(UTC) - timedelta(days=30),
            withdrawn_at=datetime.now(UTC),
        )
        consent.withdrawal_reason = "No longer needed"
        consent.withdrawal_ip_address = "192.168.1.2"
        consent.withdrawal_user_agent = "TestBrowser/2.0"
        consent.withdrawal_evidence_object_ref = "inline:withdrawal:test"
        session = create_mock_session(consent)

        service = ConsentService(session)
        evidence = await service.export_consent_evidence(
            recipient_party_id=consent.recipient_party_id,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert evidence["withdrawal_evidence"] is not None
        assert "withdrawn_at" in evidence["withdrawal_evidence"]
        assert evidence["withdrawal_evidence"]["reason"] == "No longer needed"
        assert "ip_address" in evidence["withdrawal_evidence"]

    @pytest.mark.asyncio
    async def test_export_evidence_raises_when_not_found(self):
        """export_consent_evidence raises ConsentNotFoundError if no record."""
        session = create_mock_session(None)

        service = ConsentService(session)

        with pytest.raises(ConsentNotFoundError):
            await service.export_consent_evidence(
                recipient_party_id=uuid4(),
                consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            )


# =============================================================================
# Test ConsentRecord Dataclass
# =============================================================================


class TestConsentRecord:
    """Tests for ConsentRecord dataclass."""

    def test_consent_record_is_immutable(self):
        """ConsentRecord cannot be modified after creation."""
        record = ConsentRecord(
            consent_id=uuid4(),
            recipient_party_id=uuid4(),
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            state=ConsentState.GRANTED,
            consented_at=datetime.now(UTC),
            consented_by=uuid4(),
            withdrawn_at=None,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        with pytest.raises(AttributeError):
            record.state = ConsentState.WITHDRAWN  # type: ignore


# =============================================================================
# Test ConsentEvidence Dataclass
# =============================================================================


class TestConsentEvidence:
    """Tests for ConsentEvidence dataclass."""

    def test_consent_evidence_is_immutable(self):
        """ConsentEvidence cannot be modified after creation."""
        evidence = ConsentEvidence(
            consent_id=uuid4(),
            recipient_party_id=uuid4(),
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            action="grant",
            action_time=datetime.now(UTC),
            actor_party_id=uuid4(),
            ip_address="192.168.1.1",
            user_agent="TestBrowser/1.0",
            consent_text_hash="abc123",
            metadata=None,
            evidence_hash="deadbeef",
        )

        with pytest.raises(AttributeError):
            evidence.action = "withdraw"  # type: ignore


# =============================================================================
# Test Lifecycle Service Integration
# =============================================================================


class TestLifecycleConsentIntegration:
    """Tests for consent integration with delivery lifecycle."""

    @pytest.mark.asyncio
    async def test_jurisdiction_profile_has_consent_flag(self):
        """JurisdictionProfile includes requires_recipient_consent flag."""
        from qerds.services.lifecycle import JURISDICTION_PROFILES

        assert "fr_lre" in JURISDICTION_PROFILES
        fr_lre = JURISDICTION_PROFILES["fr_lre"]
        assert fr_lre.requires_recipient_consent is True

        assert "eidas" in JURISDICTION_PROFILES
        eidas = JURISDICTION_PROFILES["eidas"]
        assert eidas.requires_recipient_consent is False

    @pytest.mark.asyncio
    async def test_consent_required_error_exists(self):
        """ConsentRequiredForDeliveryError exception exists."""
        from qerds.services.lifecycle import ConsentRequiredForDeliveryError

        recipient_id = uuid4()
        error = ConsentRequiredForDeliveryError(
            recipient_party_id=recipient_id,
            jurisdiction_profile="fr_lre",
        )

        assert error.recipient_party_id == recipient_id
        assert error.jurisdiction_profile == "fr_lre"
        assert "consent required" in str(error).lower()


# =============================================================================
# Test Exception Classes
# =============================================================================


class TestExceptionClasses:
    """Tests for consent exception classes."""

    def test_consent_not_found_error(self):
        """ConsentNotFoundError includes context."""
        recipient_id = uuid4()
        error = ConsentNotFoundError(
            recipient_id,
            ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert error.recipient_party_id == recipient_id
        assert error.consent_type == ConsentType.FR_LRE_ELECTRONIC_DELIVERY
        assert str(recipient_id) in str(error)

    def test_consent_required_error(self):
        """ConsentRequiredError includes context."""
        recipient_id = uuid4()
        error = ConsentRequiredError(
            recipient_id,
            ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        assert error.recipient_party_id == recipient_id
        assert error.consent_type == ConsentType.FR_LRE_ELECTRONIC_DELIVERY

    def test_consent_already_granted_error(self):
        """ConsentAlreadyGrantedError includes consent ID."""
        consent_id = uuid4()
        error = ConsentAlreadyGrantedError(consent_id)

        assert error.consent_id == consent_id
        assert str(consent_id) in str(error)

    def test_invalid_consent_state_error(self):
        """InvalidConsentStateError includes state and operation."""
        consent_id = uuid4()
        error = InvalidConsentStateError(
            consent_id,
            ConsentState.PENDING,
            "withdraw",
        )

        assert error.consent_id == consent_id
        assert error.current_state == ConsentState.PENDING
        assert error.operation == "withdraw"
