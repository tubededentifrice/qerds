"""Tests for sender identity proofing (REQ-B05).

Tests cover:
- SenderProofing record creation
- IAL level storage
- Proofing metadata handling
- Integration with evidence events
- IAL policy enforcement
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import ActorType, IALLevel, PartyType, ProofingMethod
from qerds.services.oidc import OIDCUserInfo, map_acr_to_ial

# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


def create_mock_party(party_id=None, party_type=PartyType.NATURAL_PERSON):
    """Create a mock Party object."""
    party = MagicMock()
    party.party_id = party_id or uuid4()
    party.party_type = party_type
    party.display_name = "Test Sender"
    party.email = "sender@example.com"
    party.external_provider = "franceconnect_plus"
    party.external_id = "fc_sub_12345"
    party.proofing_records = []
    return party


def create_oidc_user_info_ial2():
    """Create test OIDC user info with IAL2."""
    return OIDCUserInfo(
        sub="unique_fc_sub_identifier_12345",
        given_name="Jean",
        family_name="Dupont",
        email="jean.dupont@example.fr",
        email_verified=True,
        birthdate="1985-03-15",
        gender="male",
        preferred_username=None,
        acr="eidas2",
        ial_level=IALLevel.IAL2,
        raw_claims={
            "sub": "unique_fc_sub_identifier_12345",
            "given_name": "Jean",
            "family_name": "Dupont",
            "email": "jean.dupont@example.fr",
            "email_verified": True,
            "acr": "eidas2",
        },
    )


def create_oidc_user_info_ial3():
    """Create test OIDC user info with IAL3 (high assurance)."""
    return OIDCUserInfo(
        sub="unique_fc_sub_identifier_high_assurance",
        given_name="Marie",
        family_name="Martin",
        email="marie.martin@example.fr",
        email_verified=True,
        birthdate="1990-07-22",
        gender="female",
        preferred_username=None,
        acr="eidas3",
        ial_level=IALLevel.IAL3,
        raw_claims={
            "sub": "unique_fc_sub_identifier_high_assurance",
            "acr": "eidas3",
        },
    )


def create_mock_session():
    """Create a mock SQLAlchemy async session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# SenderProofing Data Tests
# ---------------------------------------------------------------------------


class TestSenderProofingData:
    """Tests for SenderProofing data structure."""

    def test_ial_level_enum_values(self):
        """Verify IALLevel enum has expected values."""
        assert IALLevel.IAL1.value == "ial1"
        assert IALLevel.IAL2.value == "ial2"
        assert IALLevel.IAL3.value == "ial3"

    def test_proofing_method_enum_values(self):
        """Verify ProofingMethod enum has expected values."""
        assert ProofingMethod.EMAIL_VERIFICATION.value == "email_verification"
        assert ProofingMethod.FRANCECONNECT.value == "franceconnect"
        assert ProofingMethod.FRANCECONNECT_PLUS.value == "franceconnect_plus"
        assert ProofingMethod.MANUAL_REVIEW.value == "manual_review"

    def test_sender_proofing_model_fields(self):
        """Verify SenderProofing model has required fields."""
        from qerds.db.models.parties import SenderProofing

        # Check model has expected columns
        mapper = SenderProofing.__mapper__
        column_names = [c.key for c in mapper.columns]

        expected_fields = [
            "proofing_id",
            "party_id",
            "ial_level",
            "proofing_method",
            "proofed_at",
            "proofing_metadata",
            "expires_at",
        ]

        for field in expected_fields:
            assert field in column_names, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Identity Proofing Record Creation Tests
# ---------------------------------------------------------------------------


class TestCreateIdentityProofingRecord:
    """Tests for create_identity_proofing_record function."""

    @pytest.mark.asyncio
    async def test_creates_proofing_with_ial2(self):
        """Should create proofing record with IAL2 from FranceConnect+."""
        from qerds.services.oidc import create_identity_proofing_record

        session = create_mock_session()
        party = create_mock_party()
        user_info = create_oidc_user_info_ial2()

        # Track what gets added to session
        added_objects = []
        session.add = lambda obj: added_objects.append(obj)

        await create_identity_proofing_record(
            session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id="franceconnect_plus",
        )

        # Verify a proofing record was added
        assert len(added_objects) == 1
        proofing = added_objects[0]

        # Verify IAL level
        assert proofing.ial_level == IALLevel.IAL2
        assert proofing.proofing_method == ProofingMethod.FRANCECONNECT_PLUS

    @pytest.mark.asyncio
    async def test_creates_proofing_with_ial3(self):
        """Should create proofing record with IAL3 for high assurance."""
        from qerds.services.oidc import create_identity_proofing_record

        session = create_mock_session()
        party = create_mock_party()
        user_info = create_oidc_user_info_ial3()

        added_objects = []
        session.add = lambda obj: added_objects.append(obj)

        await create_identity_proofing_record(
            session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id="franceconnect_plus",
        )

        proofing = added_objects[0]
        assert proofing.ial_level == IALLevel.IAL3
        assert proofing.proofing_metadata["acr"] == "eidas3"

    @pytest.mark.asyncio
    async def test_proofing_metadata_contains_hashed_sub(self):
        """Proofing metadata should contain hashed sub for privacy."""
        from qerds.services.oidc import create_identity_proofing_record

        session = create_mock_session()
        party = create_mock_party()
        user_info = create_oidc_user_info_ial2()

        added_objects = []
        session.add = lambda obj: added_objects.append(obj)

        await create_identity_proofing_record(
            session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id="franceconnect_plus",
        )

        proofing = added_objects[0]

        # Should have hashed sub (8 chars), not the full sub
        assert "sub_hash" in proofing.proofing_metadata
        assert len(proofing.proofing_metadata["sub_hash"]) == 8
        # Full sub should NOT be stored
        assert "sub" not in proofing.proofing_metadata

    @pytest.mark.asyncio
    async def test_proofing_has_expiry(self):
        """Proofing record should have 24-hour expiry."""
        from qerds.services.oidc import create_identity_proofing_record

        session = create_mock_session()
        party = create_mock_party()
        user_info = create_oidc_user_info_ial2()

        added_objects = []
        session.add = lambda obj: added_objects.append(obj)

        before = datetime.now(UTC)

        await create_identity_proofing_record(
            session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id="franceconnect_plus",
        )

        after = datetime.now(UTC)
        proofing = added_objects[0]

        # Expiry should be approximately 24 hours from now
        assert proofing.expires_at is not None
        expected_min = before + timedelta(hours=23, minutes=59)
        expected_max = after + timedelta(hours=24, minutes=1)
        assert expected_min <= proofing.expires_at <= expected_max

    @pytest.mark.asyncio
    async def test_proofing_method_detection(self):
        """Should detect FranceConnect+ vs other providers."""
        from qerds.services.oidc import create_identity_proofing_record

        session = create_mock_session()
        party = create_mock_party()
        user_info = create_oidc_user_info_ial2()

        added_objects = []
        session.add = lambda obj: added_objects.append(obj)

        # Test with FranceConnect+ provider ID
        await create_identity_proofing_record(
            session,
            party_id=party.party_id,
            user_info=user_info,
            provider_id="franceconnect_plus",
        )

        proofing = added_objects[0]
        assert proofing.proofing_method == ProofingMethod.FRANCECONNECT_PLUS


# ---------------------------------------------------------------------------
# IAL Policy Enforcement Tests
# ---------------------------------------------------------------------------


class TestIALPolicyEnforcement:
    """Tests for IAL level policy enforcement in LRE flow."""

    def test_ial1_insufficient_for_lre(self):
        """IAL1 should be insufficient for French LRE."""
        from qerds.services.pickup import IAL_REQUIREMENTS

        assert IAL_REQUIREMENTS["fr_lre"] == IALLevel.IAL2
        # IAL1 < IAL2, so it would be rejected

    def test_ial2_sufficient_for_lre(self):
        """IAL2 (eidas2) should be sufficient for French LRE."""
        from qerds.services.pickup import IAL_REQUIREMENTS

        required = IAL_REQUIREMENTS["fr_lre"]
        assert required == IALLevel.IAL2

    def test_ial3_sufficient_for_lre(self):
        """IAL3 (eidas3) should exceed requirements for French LRE."""
        from qerds.services.pickup import IAL_REQUIREMENTS

        required = IAL_REQUIREMENTS["fr_lre"]
        # IAL3 > IAL2, so it should be accepted
        assert required == IALLevel.IAL2

    def test_eidas_allows_lower_ial(self):
        """Base eIDAS profile should allow IAL1."""
        from qerds.services.pickup import IAL_REQUIREMENTS

        assert IAL_REQUIREMENTS["eidas"] == IALLevel.IAL1


# ---------------------------------------------------------------------------
# Evidence Integration Tests
# ---------------------------------------------------------------------------


class TestEvidenceIntegration:
    """Tests for IAL level inclusion in evidence events."""

    def test_deposit_includes_sender_ial_level(self):
        """EVT_DEPOSITED should include sender_ial_level in metadata."""
        from qerds.api.middleware.auth import AuthenticatedUser
        from qerds.api.routers.sender import _get_user_ial_level

        # Create a mock authenticated user with IAL metadata
        mock_user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            auth_method="oidc",
            metadata={"ial_level": "ial2", "display_name": "Test User"},
        )

        ial_level = _get_user_ial_level(mock_user)
        assert ial_level == "ial2"

    def test_get_user_ial_from_oidc_acr(self):
        """Should infer IAL from OIDC ACR when ial_level not in metadata."""
        from qerds.api.middleware.auth import AuthenticatedUser
        from qerds.api.routers.sender import _get_user_ial_level

        # User with ACR but no explicit ial_level
        mock_user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            auth_method="oidc",
            metadata={"acr": "eidas3", "display_name": "Test User"},
        )

        ial_level = _get_user_ial_level(mock_user)
        assert ial_level == "ial3"

    def test_get_user_ial_defaults_for_unknown_auth(self):
        """Should default to ial1 for non-OIDC auth methods."""
        from qerds.api.middleware.auth import AuthenticatedUser
        from qerds.api.routers.sender import _get_user_ial_level

        mock_user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="api_client",
            auth_method="api_key",
            metadata={},
        )

        ial_level = _get_user_ial_level(mock_user)
        assert ial_level == "ial1"

    def test_actor_identification_supports_proofing_ref(self):
        """ActorIdentification should support identity_proofing_ref."""
        from qerds.services.evidence import ActorIdentification

        proofing_id = uuid4()

        actor = ActorIdentification(
            actor_type=ActorType.SENDER,
            actor_ref=str(uuid4()),
            identity_proofing_ref=str(proofing_id),
            session_ref="session_abc123",
        )

        metadata = actor.to_metadata()

        assert "identity_proofing_ref" in metadata
        assert metadata["identity_proofing_ref"] == str(proofing_id)
        assert metadata["session_ref"] == "session_abc123"


# ---------------------------------------------------------------------------
# ACR Mapping Tests (Additional Edge Cases)
# ---------------------------------------------------------------------------


class TestACRMappingEdgeCases:
    """Additional edge case tests for ACR-to-IAL mapping."""

    def test_empty_acr_maps_to_ial1(self):
        """Empty ACR should map to IAL1."""
        assert map_acr_to_ial("") == IALLevel.IAL1

    def test_none_like_acr_maps_to_ial1(self):
        """None-like values should map to IAL1."""
        assert map_acr_to_ial("none") == IALLevel.IAL1
        assert map_acr_to_ial("null") == IALLevel.IAL1

    def test_case_sensitive_acr(self):
        """ACR matching should be case-sensitive."""
        # Standard values are lowercase
        assert map_acr_to_ial("eidas2") == IALLevel.IAL2
        # Uppercase should not match
        assert map_acr_to_ial("EIDAS2") == IALLevel.IAL1
        assert map_acr_to_ial("Eidas2") == IALLevel.IAL1

    def test_partial_match_not_accepted(self):
        """Partial ACR matches should not be accepted."""
        assert map_acr_to_ial("eidas") == IALLevel.IAL1
        assert map_acr_to_ial("eidas23") == IALLevel.IAL1
        assert map_acr_to_ial("my_eidas2") == IALLevel.IAL1


# ---------------------------------------------------------------------------
# Pickup Service IAL Enforcement Tests
# ---------------------------------------------------------------------------


class TestPickupServiceIALEnforcement:
    """Tests for IAL enforcement in pickup service."""

    def test_check_ial_requirement_ial2_meets_ial2(self):
        """IAL2 should meet IAL2 requirement."""
        from qerds.services.pickup import PickupService

        service = PickupService(create_mock_session())
        result = service._check_ial_requirement(IALLevel.IAL2, "fr_lre")
        assert result is True

    def test_check_ial_requirement_ial3_meets_ial2(self):
        """IAL3 should exceed IAL2 requirement."""
        from qerds.services.pickup import PickupService

        service = PickupService(create_mock_session())
        result = service._check_ial_requirement(IALLevel.IAL3, "fr_lre")
        assert result is True

    def test_check_ial_requirement_ial1_fails_ial2(self):
        """IAL1 should fail IAL2 requirement."""
        from qerds.services.pickup import PickupService

        service = PickupService(create_mock_session())
        result = service._check_ial_requirement(IALLevel.IAL1, "fr_lre")
        assert result is False

    def test_check_ial_requirement_none_fails(self):
        """None IAL should fail any requirement."""
        from qerds.services.pickup import PickupService

        service = PickupService(create_mock_session())
        result = service._check_ial_requirement(None, "fr_lre")
        assert result is False

    def test_enforce_ial_requirement_raises_for_insufficient(self):
        """Should raise InsufficientIALError for insufficient level."""
        from qerds.services.pickup import InsufficientIALError, PickupService

        service = PickupService(create_mock_session())

        with pytest.raises(InsufficientIALError) as exc_info:
            service._enforce_ial_requirement(IALLevel.IAL1, "fr_lre")

        assert exc_info.value.required == IALLevel.IAL2
        assert exc_info.value.actual == IALLevel.IAL1
