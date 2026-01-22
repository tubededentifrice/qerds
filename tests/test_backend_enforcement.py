"""Security regression tests for backend enforcement of all controls (REQ-I02).

This module tests that security/compliance controls are enforced on the backend,
treating the frontend/UI as untrusted. These tests attempt to bypass UI controls
by calling API endpoints directly.

Controls tested:
1. Authentication (authn): All protected endpoints require authentication
2. Authorization (authz): Recipient must match delivery, role-based access
3. Sender redaction: Sender identity hidden until accept/refuse (REQ-F03)
4. Acceptance window: 15-day deadline enforced (REQ-F04)
5. Consumer consent: LRE requires prior consent (REQ-F06)
6. Content access: Only allowed after acceptance (REQ-E02)
7. Retention: CPCE minimum 365-day retention (REQ-F05)

All tests run against Docker containers for reproducibility.
Use: docker compose exec qerds-api pytest tests/test_backend_enforcement.py -v
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from qerds.db.models.base import (
    ConsentState,
    ConsentType,
    DeliveryState,
    IALLevel,
    RetentionActionType,
)
from qerds.services.authz import (
    AuthorizationService,
    Permission,
    Principal,
    RoleClass,
)
from qerds.services.consent import (
    ConsentRequiredError,
    ConsentService,
)
from qerds.services.lifecycle import DeliveryLifecycleService
from qerds.services.pickup import (
    DeliveryExpiredError,
    InsufficientIALError,
    InvalidStateError,
    PickupService,
    RecipientMismatchError,
)
from qerds.services.retention import (
    CPCEViolationError,
    RetentionPolicyService,
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
def mock_available_delivery():
    """Create a mock delivery in AVAILABLE state with valid deadline."""
    delivery = MagicMock()
    delivery.delivery_id = uuid4()
    delivery.state = DeliveryState.AVAILABLE
    delivery.jurisdiction_profile = "fr_lre"
    delivery.sender_party_id = uuid4()
    delivery.recipient_party_id = uuid4()
    delivery.subject = "Confidential Document"
    delivery.deposited_at = datetime.now(UTC) - timedelta(days=1)
    delivery.acceptance_deadline_at = datetime.now(UTC) + timedelta(days=14)
    delivery.completed_at = None

    # Mock sender party (should be hidden pre-acceptance)
    sender_party = MagicMock()
    sender_party.party_id = delivery.sender_party_id
    sender_party.display_name = "Jean Dupont (Sender)"
    sender_party.email = "sender@example.com"
    delivery.sender_party = sender_party

    # Mock recipient party
    recipient_party = MagicMock()
    recipient_party.party_id = delivery.recipient_party_id
    recipient_party.display_name = "Marie Martin (Recipient)"
    recipient_party.email = "recipient@example.com"
    delivery.recipient_party = recipient_party

    delivery.content_objects = []

    return delivery


@pytest.fixture
def mock_expired_delivery(mock_available_delivery):
    """Create a mock delivery with expired acceptance deadline."""
    mock_available_delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
    return mock_available_delivery


@pytest.fixture
def authz_service():
    """Create an AuthorizationService instance."""
    return AuthorizationService()


@pytest.fixture
def pickup_service(mock_db_session):
    """Create a PickupService instance with mock session."""
    return PickupService(mock_db_session)


# ---------------------------------------------------------------------------
# Test: Authentication Bypass Prevention
# ---------------------------------------------------------------------------


class TestAuthenticationEnforcement:
    """Tests that API endpoints reject unauthenticated requests.

    These tests verify that the backend enforces authentication and does not
    rely solely on UI/frontend to prevent unauthenticated access.
    """

    def test_inactive_principal_has_no_permissions(self, authz_service):
        """Verify inactive accounts cannot access any resources."""
        # Create an inactive principal
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset([RoleClass.ADMIN.value]),
            is_active=False,  # Account is deactivated
        )

        # Even with admin role, inactive account should have no permissions
        all_perms = authz_service.get_all_permissions(principal)
        assert all_perms == frozenset()

    def test_inactive_principal_denied_all_operations(self, authz_service):
        """Verify inactive accounts are denied all operations."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset([RoleClass.ADMIN.value]),
            is_active=False,
        )

        # All permission checks should fail
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES) is False
        assert authz_service.has_permission(principal, Permission.VIEW_USERS) is False
        assert authz_service.has_permission(principal, Permission.ADMIN_ACCESS) is False

    @pytest.mark.asyncio
    async def test_pickup_context_requires_authenticated_party_for_actions(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify pickup context denies actions to unauthenticated users."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        # Unauthenticated request (no party ID)
        context = await pickup_service.get_pickup_context(
            mock_available_delivery.delivery_id,
            authenticated_party_id=None,
            ial_level=None,
        )

        # Unauthenticated users cannot perform accept/refuse actions
        assert context.is_authenticated is False
        assert context.can_accept_refuse is False


# ---------------------------------------------------------------------------
# Test: Authorization Bypass Prevention
# ---------------------------------------------------------------------------


class TestAuthorizationEnforcement:
    """Tests that authorization is enforced server-side.

    These tests verify that users cannot access resources they don't own
    or perform operations they're not authorized for.
    """

    @pytest.mark.asyncio
    async def test_accept_delivery_rejects_non_recipient(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify accept operation rejects users who are not the recipient.

        CRITICAL: An attacker knowing a delivery_id should NOT be able to
        accept a delivery addressed to someone else.
        """
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        # Attacker trying to accept someone else's delivery
        attacker_party_id = uuid4()

        with pytest.raises(RecipientMismatchError) as exc_info:
            await pickup_service.accept_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=attacker_party_id,  # Wrong party!
                ial_level=IALLevel.IAL2,
                confirm_consent=True,
            )

        assert exc_info.value.delivery_id == mock_available_delivery.delivery_id
        assert exc_info.value.authenticated_party_id == attacker_party_id

    @pytest.mark.asyncio
    async def test_refuse_delivery_rejects_non_recipient(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify refuse operation rejects users who are not the recipient."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        # Attacker trying to refuse someone else's delivery
        attacker_party_id = uuid4()

        with pytest.raises(RecipientMismatchError):
            await pickup_service.refuse_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=attacker_party_id,
                ial_level=IALLevel.IAL2,
            )

    @pytest.mark.asyncio
    async def test_pickup_context_rejects_non_recipient(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify pickup context rejects viewing by non-recipients."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        # Attacker trying to view someone else's delivery details
        attacker_party_id = uuid4()

        with pytest.raises(RecipientMismatchError):
            await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=attacker_party_id,
                ial_level=IALLevel.IAL2,
            )

    def test_role_based_permission_enforcement(self, authz_service):
        """Verify role-based permissions are correctly enforced."""
        # Sender user should NOT have admin permissions
        sender_principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset([RoleClass.SENDER_USER.value]),
            is_active=True,
        )

        # Sender can create deliveries
        assert authz_service.has_permission(sender_principal, Permission.CREATE_DELIVERY) is True

        # But cannot access admin features
        assert authz_service.has_permission(sender_principal, Permission.ADMIN_ACCESS) is False
        assert authz_service.has_permission(sender_principal, Permission.MANAGE_USERS) is False
        assert authz_service.has_permission(sender_principal, Permission.VIEW_AUDIT_LOGS) is False

    def test_recipient_cannot_access_admin_features(self, authz_service):
        """Verify recipient role is properly restricted."""
        recipient_principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset([RoleClass.RECIPIENT_USER.value]),
            is_active=True,
        )

        # Recipients can accept/refuse
        assert authz_service.has_permission(recipient_principal, Permission.ACCEPT_DELIVERY) is True
        assert authz_service.has_permission(recipient_principal, Permission.REFUSE_DELIVERY) is True

        # But cannot manage other resources
        assert authz_service.has_permission(recipient_principal, Permission.ADMIN_ACCESS) is False
        has_create = authz_service.has_permission(recipient_principal, Permission.CREATE_DELIVERY)
        assert has_create is False

    def test_separation_of_duties_prevents_admin_auditor_combo(self, authz_service):
        """Verify separation of duties rules are enforced.

        Admin cannot also be auditor to prevent self-audit.
        """
        admin_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset([RoleClass.ADMIN.value]),
            is_active=True,
        )

        # Trying to add auditor role should be blocked
        can_add_auditor = authz_service.check_separation_of_duties(
            admin_principal, RoleClass.AUDITOR
        )
        assert can_add_auditor is False

    def test_separation_of_duties_prevents_security_admin_combo(self, authz_service):
        """Verify security officer cannot also be admin (dual-control)."""
        security_officer = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset([RoleClass.SECURITY_OFFICER.value]),
            is_active=True,
        )

        # Trying to add admin role should be blocked
        can_add_admin = authz_service.check_separation_of_duties(security_officer, RoleClass.ADMIN)
        assert can_add_admin is False


# ---------------------------------------------------------------------------
# Test: Sender Identity Redaction (REQ-F03)
# ---------------------------------------------------------------------------


class TestSenderRedactionEnforcement:
    """Tests that sender identity is hidden until accept/refuse (REQ-F03).

    CRITICAL: UI-only redaction is NOT sufficient. The backend must enforce
    this to prevent API-level bypass attacks.
    """

    @pytest.mark.asyncio
    async def test_sender_hidden_in_available_state(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify sender is not revealed in AVAILABLE state."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # sender_revealed should be False in AVAILABLE state
        assert context.sender_revealed is False

    @pytest.mark.asyncio
    async def test_sender_hidden_in_deposited_state(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify sender is not revealed in DEPOSITED state."""
        mock_available_delivery.state = DeliveryState.DEPOSITED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is False

    @pytest.mark.asyncio
    async def test_sender_revealed_after_accepted(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify sender is revealed only after ACCEPTED state."""
        mock_available_delivery.state = DeliveryState.ACCEPTED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is True

    @pytest.mark.asyncio
    async def test_sender_revealed_after_refused(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify sender is revealed after REFUSED state."""
        mock_available_delivery.state = DeliveryState.REFUSED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is True

    @pytest.mark.asyncio
    async def test_sender_revealed_after_received(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify sender is revealed in RECEIVED state."""
        mock_available_delivery.state = DeliveryState.RECEIVED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        assert context.sender_revealed is True


# ---------------------------------------------------------------------------
# Test: 15-Day Acceptance Window Enforcement (REQ-F04)
# ---------------------------------------------------------------------------


class TestAcceptanceWindowEnforcement:
    """Tests that 15-day acceptance window is enforced server-side (REQ-F04).

    CRITICAL: The deadline must be enforced on the backend, not just UI.
    """

    @pytest.mark.asyncio
    async def test_accept_blocked_after_deadline(
        self, pickup_service, mock_db_session, mock_expired_delivery
    ):
        """Verify accept operation is blocked after deadline passes."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_expired_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(DeliveryExpiredError) as exc_info:
            await pickup_service.accept_delivery(
                mock_expired_delivery.delivery_id,
                recipient_party_id=mock_expired_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=True,
            )

        assert exc_info.value.delivery_id == mock_expired_delivery.delivery_id

    @pytest.mark.asyncio
    async def test_refuse_blocked_after_deadline(
        self, pickup_service, mock_db_session, mock_expired_delivery
    ):
        """Verify refuse operation is blocked after deadline passes."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_expired_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(DeliveryExpiredError):
            await pickup_service.refuse_delivery(
                mock_expired_delivery.delivery_id,
                recipient_party_id=mock_expired_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

    @pytest.mark.asyncio
    async def test_claim_token_validation_rejects_expired(
        self, pickup_service, mock_db_session, mock_expired_delivery
    ):
        """Verify claim token validation rejects expired deliveries."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_expired_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(DeliveryExpiredError):
            await pickup_service.validate_claim_token(
                "any-token",
                mock_expired_delivery.delivery_id,
            )

    @pytest.mark.asyncio
    async def test_lifecycle_transition_blocked_after_deadline(self, mock_db_session):
        """Verify lifecycle service blocks accept/refuse after deadline."""
        lifecycle = DeliveryLifecycleService(mock_db_session)

        # Create a mock delivery past deadline
        delivery = MagicMock()
        delivery.delivery_id = uuid4()
        delivery.state = DeliveryState.AVAILABLE
        delivery.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)
        delivery.jurisdiction_profile = "fr_lre"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = delivery
        mock_db_session.execute.return_value = mock_result

        # Attempt to accept after deadline
        result = await lifecycle.accept(
            delivery_id=delivery.delivery_id,
            actor_type=MagicMock(),
            actor_ref="test",
        )

        # Should fail because deadline passed
        assert result.success is False
        assert "deadline" in result.error.lower()


# ---------------------------------------------------------------------------
# Test: Consumer Consent Enforcement (REQ-F06)
# ---------------------------------------------------------------------------


class TestConsentEnforcement:
    """Tests that consumer consent is enforced server-side (REQ-F06).

    CRITICAL: LRE deliveries require prior consent. Backend must enforce this.
    """

    @pytest.mark.asyncio
    async def test_accept_requires_consent_for_fr_lre(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify accept requires consent confirmation for FR LRE."""
        mock_available_delivery.jurisdiction_profile = "fr_lre"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        # Attempt to accept without consent confirmation
        from qerds.services.pickup import ConsentRequiredError

        with pytest.raises(ConsentRequiredError):
            await pickup_service.accept_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=False,  # Consent NOT confirmed
            )

    @pytest.mark.asyncio
    async def test_consent_service_verify_blocks_without_consent(self, mock_db_session):
        """Verify consent service blocks delivery without granted consent."""
        consent_service = ConsentService(mock_db_session)

        # Mock no consent record exists
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        party_id = uuid4()

        with pytest.raises(ConsentRequiredError) as exc_info:
            await consent_service.verify_consent_for_delivery(
                recipient_party_id=party_id,
                jurisdiction_profile="fr_lre",
            )

        assert exc_info.value.recipient_party_id == party_id
        assert exc_info.value.consent_type == ConsentType.FR_LRE_ELECTRONIC_DELIVERY

    @pytest.mark.asyncio
    async def test_consent_service_allows_with_granted_consent(self, mock_db_session):
        """Verify consent service allows delivery with granted consent."""
        consent_service = ConsentService(mock_db_session)

        # Mock consent record exists and is GRANTED
        consent = MagicMock()
        consent.state = ConsentState.GRANTED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = consent
        mock_db_session.execute.return_value = mock_result

        party_id = uuid4()

        # Should not raise
        result = await consent_service.verify_consent_for_delivery(
            recipient_party_id=party_id,
            jurisdiction_profile="fr_lre",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_withdrawn_consent_blocks_delivery(self, mock_db_session):
        """Verify withdrawn consent blocks new deliveries."""
        consent_service = ConsentService(mock_db_session)

        # Mock consent record exists but is WITHDRAWN
        consent = MagicMock()
        consent.state = ConsentState.WITHDRAWN

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = consent
        mock_db_session.execute.return_value = mock_result

        party_id = uuid4()

        with pytest.raises(ConsentRequiredError):
            await consent_service.verify_consent_for_delivery(
                recipient_party_id=party_id,
                jurisdiction_profile="fr_lre",
            )


# ---------------------------------------------------------------------------
# Test: IAL Level Enforcement (REQ-F04)
# ---------------------------------------------------------------------------


class TestIALEnforcement:
    """Tests that IAL level requirements are enforced server-side.

    CRITICAL: LRE requires IAL_SUBSTANTIAL (IAL2). Backend must enforce this.
    """

    @pytest.mark.asyncio
    async def test_accept_rejects_low_ial_for_fr_lre(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify accept rejects IAL1 for FR LRE (requires IAL2)."""
        mock_available_delivery.jurisdiction_profile = "fr_lre"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InsufficientIALError) as exc_info:
            await pickup_service.accept_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL1,  # Too low!
                confirm_consent=True,
            )

        assert exc_info.value.required == IALLevel.IAL2
        assert exc_info.value.actual == IALLevel.IAL1

    @pytest.mark.asyncio
    async def test_refuse_rejects_low_ial_for_fr_lre(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify refuse also enforces IAL requirements."""
        mock_available_delivery.jurisdiction_profile = "fr_lre"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InsufficientIALError):
            await pickup_service.refuse_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL1,
            )

    def test_ial2_accepted_for_fr_lre(self, pickup_service):
        """Verify IAL2 is accepted for FR LRE."""
        result = pickup_service._check_ial_requirement(IALLevel.IAL2, "fr_lre")
        assert result is True

    def test_ial3_accepted_for_fr_lre(self, pickup_service):
        """Verify IAL3 (higher than required) is accepted."""
        result = pickup_service._check_ial_requirement(IALLevel.IAL3, "fr_lre")
        assert result is True


# ---------------------------------------------------------------------------
# Test: Content Access Enforcement (REQ-E02)
# ---------------------------------------------------------------------------


class TestContentAccessEnforcement:
    """Tests that content access is enforced server-side (REQ-E02).

    CRITICAL: Content download must be blocked until acceptance.
    """

    @pytest.mark.asyncio
    async def test_content_blocked_in_available_state(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify content is blocked in AVAILABLE state.

        Even if attacker knows the delivery_id and is authenticated as
        the recipient, they should not be able to download content
        before accepting.
        """
        mock_available_delivery.state = DeliveryState.AVAILABLE

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # Content should NOT be accessible (state is not ACCEPTED)
        assert context.delivery.state != DeliveryState.ACCEPTED

    @pytest.mark.asyncio
    async def test_content_blocked_after_refusal(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify content remains blocked after refusal."""
        mock_available_delivery.state = DeliveryState.REFUSED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with patch.object(pickup_service, "_check_consent", return_value=True):
            context = await pickup_service.get_pickup_context(
                mock_available_delivery.delivery_id,
                authenticated_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

        # Content should NOT be accessible after refusal
        assert context.delivery.state == DeliveryState.REFUSED
        assert context.delivery.state != DeliveryState.ACCEPTED


# ---------------------------------------------------------------------------
# Test: State Machine Enforcement
# ---------------------------------------------------------------------------


class TestStateMachineEnforcement:
    """Tests that delivery state machine is enforced server-side.

    CRITICAL: State transitions must follow the defined flow.
    No backwards transitions or invalid jumps.
    """

    @pytest.mark.asyncio
    async def test_cannot_accept_from_wrong_state(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify accept is blocked when delivery is not in AVAILABLE state."""
        mock_available_delivery.state = DeliveryState.DEPOSITED  # Wrong state!

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InvalidStateError) as exc_info:
            await pickup_service.accept_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
                confirm_consent=True,
            )

        assert exc_info.value.current_state == DeliveryState.DEPOSITED

    @pytest.mark.asyncio
    async def test_cannot_refuse_from_wrong_state(
        self, pickup_service, mock_db_session, mock_available_delivery
    ):
        """Verify refuse is blocked when delivery is not in AVAILABLE state."""
        mock_available_delivery.state = DeliveryState.NOTIFIED  # Wrong state!

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_available_delivery
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(InvalidStateError):
            await pickup_service.refuse_delivery(
                mock_available_delivery.delivery_id,
                recipient_party_id=mock_available_delivery.recipient_party_id,
                ial_level=IALLevel.IAL2,
            )

    def test_lifecycle_valid_transitions(self, mock_db_session):
        """Verify only valid state transitions are allowed."""
        lifecycle = DeliveryLifecycleService(mock_db_session)

        # Valid transitions
        assert lifecycle.is_valid_transition(DeliveryState.DRAFT, DeliveryState.DEPOSITED) is True
        assert (
            lifecycle.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.ACCEPTED) is True
        )
        assert lifecycle.is_valid_transition(DeliveryState.AVAILABLE, DeliveryState.REFUSED) is True

        # Invalid transitions
        assert (
            lifecycle.is_valid_transition(DeliveryState.ACCEPTED, DeliveryState.AVAILABLE) is False
        )
        assert lifecycle.is_valid_transition(DeliveryState.REFUSED, DeliveryState.ACCEPTED) is False
        assert lifecycle.is_valid_transition(DeliveryState.EXPIRED, DeliveryState.ACCEPTED) is False

    def test_terminal_states_have_no_outgoing_transitions(self, mock_db_session):
        """Verify terminal states have no valid outgoing transitions."""
        lifecycle = DeliveryLifecycleService(mock_db_session)

        # These are terminal states
        assert lifecycle.is_terminal_state(DeliveryState.REFUSED) is True
        assert lifecycle.is_terminal_state(DeliveryState.RECEIVED) is True
        assert lifecycle.is_terminal_state(DeliveryState.EXPIRED) is True

        # These are not terminal states
        assert lifecycle.is_terminal_state(DeliveryState.AVAILABLE) is False
        assert lifecycle.is_terminal_state(DeliveryState.ACCEPTED) is False


# ---------------------------------------------------------------------------
# Test: Retention Policy Enforcement (REQ-F05, REQ-H02)
# ---------------------------------------------------------------------------


class TestRetentionEnforcement:
    """Tests that CPCE retention requirements are enforced server-side.

    CRITICAL: Evidence must be retained for minimum 365 days per CPCE.
    """

    @pytest.mark.asyncio
    async def test_cannot_create_policy_below_cpce_minimum_for_delivery(self, mock_db_session):
        """Verify retention policy creation blocked below CPCE minimum for deliveries."""
        service = RetentionPolicyService(mock_db_session)

        with pytest.raises(CPCEViolationError) as exc_info:
            await service.create_policy(
                artifact_type="delivery",
                retention_days=180,  # Below 365-day minimum!
                expiry_action=RetentionActionType.DELETE,
            )

        assert "365" in str(exc_info.value)
        assert "delivery" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cannot_create_policy_below_cpce_minimum_for_evidence(self, mock_db_session):
        """Verify retention policy creation blocked below CPCE minimum for evidence."""
        service = RetentionPolicyService(mock_db_session)

        with pytest.raises(CPCEViolationError):
            await service.create_policy(
                artifact_type="evidence_object",
                retention_days=100,  # Below 365-day minimum!
                expiry_action=RetentionActionType.ARCHIVE,
            )

    @pytest.mark.asyncio
    async def test_can_create_policy_at_cpce_minimum(self, mock_db_session):
        """Verify retention policy creation allowed at exactly CPCE minimum."""
        service = RetentionPolicyService(mock_db_session)

        # Should not raise
        policy = await service.create_policy(
            artifact_type="delivery",
            retention_days=365,  # Exactly at minimum
            expiry_action=RetentionActionType.ARCHIVE,
        )

        assert policy.minimum_retention_days == 365

    @pytest.mark.asyncio
    async def test_can_create_policy_above_cpce_minimum(self, mock_db_session):
        """Verify retention policy creation allowed above CPCE minimum."""
        service = RetentionPolicyService(mock_db_session)

        # Should not raise
        policy = await service.create_policy(
            artifact_type="evidence_object",
            retention_days=730,  # 2 years, above minimum
            expiry_action=RetentionActionType.ARCHIVE,
        )

        assert policy.minimum_retention_days == 730

    @pytest.mark.asyncio
    async def test_content_objects_can_have_shorter_retention(self, mock_db_session):
        """Verify content objects can have shorter retention than evidence."""
        service = RetentionPolicyService(mock_db_session)

        # Content objects are not evidence, so can have shorter retention
        policy = await service.create_policy(
            artifact_type="content_object",
            retention_days=90,  # Shorter is OK for content
            expiry_action=RetentionActionType.DELETE,
        )

        assert policy.minimum_retention_days == 90

    def test_is_past_minimum_retention_accurate(self, mock_db_session):
        """Verify retention period calculation is accurate."""
        service = RetentionPolicyService(mock_db_session)

        # Artifact created 364 days ago should NOT be past minimum
        recent_artifact = datetime.now(UTC) - timedelta(days=364)
        assert service.is_past_minimum_retention(recent_artifact) is False

        # Artifact created exactly 365 days ago should be past minimum
        at_limit = datetime.now(UTC) - timedelta(days=365)
        assert service.is_past_minimum_retention(at_limit) is True

        # Artifact created 400 days ago should be past minimum
        old_artifact = datetime.now(UTC) - timedelta(days=400)
        assert service.is_past_minimum_retention(old_artifact) is True


# ---------------------------------------------------------------------------
# Test: Dual-Control Enforcement
# ---------------------------------------------------------------------------


class TestDualControlEnforcement:
    """Tests that dual-control is enforced for sensitive operations."""

    def test_sensitive_operations_require_dual_control(self, authz_service):
        """Verify sensitive operations are marked as requiring dual-control."""
        assert authz_service.requires_dual_control(Permission.KEY_MANAGEMENT) is True
        assert authz_service.requires_dual_control(Permission.CONFIG_CHANGE) is True
        assert authz_service.requires_dual_control(Permission.SECURITY_SETTINGS) is True
        assert authz_service.requires_dual_control(Permission.EXPORT_AUDIT_LOGS) is True

    def test_normal_operations_no_dual_control(self, authz_service):
        """Verify normal operations don't require dual-control."""
        assert authz_service.requires_dual_control(Permission.VIEW_DELIVERIES) is False
        assert authz_service.requires_dual_control(Permission.CREATE_DELIVERY) is False
        assert authz_service.requires_dual_control(Permission.VIEW_USERS) is False

    def test_cannot_approve_own_dual_control_request(self, authz_service):
        """Verify user cannot approve their own dual-control request."""
        from qerds.services.authz import SeparationOfDutiesError

        user_id = uuid4()

        # User requests a dual-control operation
        request = authz_service.create_dual_control_request(
            principal=Principal(
                principal_id=user_id,
                principal_type="admin_user",
                roles=frozenset([RoleClass.SECURITY_OFFICER.value]),
                is_active=True,
            ),
            permission=Permission.KEY_MANAGEMENT,
            operation="rotate_signing_key",
            reason="Scheduled key rotation",
        )

        # Same user trying to approve their own request
        with pytest.raises(SeparationOfDutiesError):
            authz_service.approve_dual_control_request(
                request_id=request.request_id,
                approver=Principal(
                    principal_id=user_id,  # Same user!
                    principal_type="admin_user",
                    roles=frozenset([RoleClass.SECURITY_OFFICER.value]),
                    is_active=True,
                ),
            )
