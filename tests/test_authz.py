"""Tests for the authorization service.

Tests cover:
- Permission and role definitions
- RBAC permission checks
- ABAC attribute-based access control
- Dual-control workflow
- Separation of duties enforcement
- require_permission decorator
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from qerds.services.authz import (
    DUAL_CONTROL_PERMISSIONS,
    ROLE_PERMISSIONS,
    ABACContext,
    AccessPurpose,
    AuthorizationError,
    AuthorizationService,
    DualControlRequest,
    DualControlRequiredError,
    Environment,
    InactiveAccountError,
    Permission,
    PermissionDeniedError,
    Principal,
    RoleClass,
    SeparationOfDutiesError,
    require_permission_decorator,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def authz_service() -> AuthorizationService:
    """Create a fresh authorization service instance."""
    return AuthorizationService()


@pytest.fixture
def admin_principal() -> Principal:
    """Create an admin principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="admin_user",
        roles=frozenset(["admin"]),
        is_active=True,
    )


@pytest.fixture
def security_officer_principal() -> Principal:
    """Create a security officer principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="admin_user",
        roles=frozenset(["security_officer"]),
        is_active=True,
    )


@pytest.fixture
def auditor_principal() -> Principal:
    """Create an auditor principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="admin_user",
        roles=frozenset(["auditor"]),
        is_active=True,
    )


@pytest.fixture
def sender_principal() -> Principal:
    """Create a sender user principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="sender_user",
        roles=frozenset(["sender_user"]),
        is_active=True,
    )


@pytest.fixture
def recipient_principal() -> Principal:
    """Create a recipient user principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="recipient_user",
        roles=frozenset(["recipient_user"]),
        is_active=True,
    )


@pytest.fixture
def inactive_principal() -> Principal:
    """Create an inactive principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="admin_user",
        roles=frozenset(["admin"]),
        is_active=False,
    )


@pytest.fixture
def superuser_principal() -> Principal:
    """Create a superuser principal for testing."""
    return Principal(
        principal_id=uuid4(),
        principal_type="admin_user",
        roles=frozenset(["admin"]),
        is_active=True,
        is_superuser=True,
    )


# ---------------------------------------------------------------------------
# Tests: Permission and RoleClass enums
# ---------------------------------------------------------------------------


class TestPermissionEnum:
    """Tests for the Permission enum."""

    def test_permission_values_are_strings(self) -> None:
        """Verify all permissions have string values."""
        for perm in Permission:
            assert isinstance(perm.value, str)
            assert len(perm.value) > 0

    def test_all_permissions_have_unique_values(self) -> None:
        """Verify no duplicate permission values."""
        values = [p.value for p in Permission]
        assert len(values) == len(set(values))

    def test_permission_string_conversion(self) -> None:
        """Verify permissions can be created from strings."""
        assert Permission("view_deliveries") == Permission.VIEW_DELIVERIES
        assert Permission("admin_access") == Permission.ADMIN_ACCESS


class TestRoleClassEnum:
    """Tests for the RoleClass enum."""

    def test_all_role_classes_defined(self) -> None:
        """Verify all expected role classes are defined."""
        expected = {
            "admin",
            "security_officer",
            "auditor",
            "support",
            "registration_officer",
            "sender_user",
            "recipient_user",
            "api_client",
        }
        actual = {rc.value for rc in RoleClass}
        assert actual == expected

    def test_role_class_string_conversion(self) -> None:
        """Verify role classes can be created from strings."""
        assert RoleClass("admin") == RoleClass.ADMIN
        assert RoleClass("sender_user") == RoleClass.SENDER_USER


# ---------------------------------------------------------------------------
# Tests: Role permission mappings
# ---------------------------------------------------------------------------


class TestRolePermissionMappings:
    """Tests for the role-to-permission mappings."""

    def test_all_role_classes_have_mappings(self) -> None:
        """Verify all role classes have permission mappings."""
        for role_class in RoleClass:
            assert role_class in ROLE_PERMISSIONS
            # Each role should have at least one permission
            assert len(ROLE_PERMISSIONS[role_class]) > 0

    def test_admin_has_admin_access(self) -> None:
        """Verify admin role has admin_access permission."""
        assert Permission.ADMIN_ACCESS in ROLE_PERMISSIONS[RoleClass.ADMIN]

    def test_admin_does_not_have_key_management(self) -> None:
        """Verify admin role does not automatically have key_management.

        Key management requires dual-control and is only granted to security officers.
        """
        assert Permission.KEY_MANAGEMENT not in ROLE_PERMISSIONS[RoleClass.ADMIN]

    def test_security_officer_has_key_management(self) -> None:
        """Verify security officer has key management permission."""
        assert Permission.KEY_MANAGEMENT in ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]

    def test_auditor_has_audit_access(self) -> None:
        """Verify auditor role has audit_access permission."""
        assert Permission.AUDIT_ACCESS in ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.VIEW_AUDIT_LOGS in ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.EXPORT_AUDIT_LOGS in ROLE_PERMISSIONS[RoleClass.AUDITOR]

    def test_sender_has_create_delivery(self) -> None:
        """Verify sender can create deliveries."""
        assert Permission.CREATE_DELIVERY in ROLE_PERMISSIONS[RoleClass.SENDER_USER]

    def test_recipient_can_accept_delivery(self) -> None:
        """Verify recipient can accept deliveries."""
        assert Permission.ACCEPT_DELIVERY in ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.REFUSE_DELIVERY in ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]

    def test_registration_officer_can_verify_identity(self) -> None:
        """Verify registration officer can verify identities."""
        assert Permission.VERIFY_IDENTITY in ROLE_PERMISSIONS[RoleClass.REGISTRATION_OFFICER]

    def test_support_has_support_permissions(self) -> None:
        """Verify support role has support case permissions."""
        assert Permission.VIEW_SUPPORT_CASES in ROLE_PERMISSIONS[RoleClass.SUPPORT]
        assert Permission.MANAGE_SUPPORT_CASES in ROLE_PERMISSIONS[RoleClass.SUPPORT]


class TestDualControlPermissions:
    """Tests for dual-control permission set."""

    def test_key_management_requires_dual_control(self) -> None:
        """Verify key management requires dual control."""
        assert Permission.KEY_MANAGEMENT in DUAL_CONTROL_PERMISSIONS

    def test_config_change_requires_dual_control(self) -> None:
        """Verify config change requires dual control."""
        assert Permission.CONFIG_CHANGE in DUAL_CONTROL_PERMISSIONS

    def test_view_deliveries_does_not_require_dual_control(self) -> None:
        """Verify normal permissions don't require dual control."""
        assert Permission.VIEW_DELIVERIES not in DUAL_CONTROL_PERMISSIONS
        assert Permission.CREATE_DELIVERY not in DUAL_CONTROL_PERMISSIONS


# ---------------------------------------------------------------------------
# Tests: Principal
# ---------------------------------------------------------------------------


class TestPrincipal:
    """Tests for the Principal dataclass."""

    def test_get_role_classes_standard_roles(self) -> None:
        """Verify role class extraction for standard roles."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "auditor"]),
        )
        role_classes = principal.get_role_classes()
        assert RoleClass.ADMIN in role_classes
        assert RoleClass.AUDITOR in role_classes

    def test_get_role_classes_ignores_custom_roles(self) -> None:
        """Verify custom roles are ignored in role class extraction."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "custom_role"]),
        )
        role_classes = principal.get_role_classes()
        assert RoleClass.ADMIN in role_classes
        assert len(role_classes) == 1  # custom_role should not be included

    def test_default_values(self) -> None:
        """Verify Principal has sensible defaults."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
        )
        assert principal.roles == frozenset()
        assert principal.explicit_permissions == frozenset()
        assert principal.is_superuser is False
        assert principal.is_active is True


# ---------------------------------------------------------------------------
# Tests: ABACContext
# ---------------------------------------------------------------------------


class TestABACContext:
    """Tests for the ABACContext dataclass."""

    def test_is_assigned_to_delivery(self) -> None:
        """Verify delivery assignment check."""
        delivery_id = uuid4()
        ctx = ABACContext(assigned_delivery_ids=frozenset([delivery_id]))
        assert ctx.is_assigned_to_delivery(delivery_id) is True
        assert ctx.is_assigned_to_delivery(uuid4()) is False

    def test_is_member_of_organization(self) -> None:
        """Verify organization membership check."""
        org_id = uuid4()
        ctx = ABACContext(organization_ids=frozenset([org_id]))
        assert ctx.is_member_of_organization(org_id) is True
        assert ctx.is_member_of_organization(uuid4()) is False

    def test_default_environment(self) -> None:
        """Verify default environment is production."""
        ctx = ABACContext()
        assert ctx.environment == Environment.PRODUCTION

    def test_default_purpose(self) -> None:
        """Verify default purpose is normal operation."""
        ctx = ABACContext()
        assert ctx.access_purpose == AccessPurpose.NORMAL_OPERATION


# ---------------------------------------------------------------------------
# Tests: AuthorizationService - RBAC
# ---------------------------------------------------------------------------


class TestAuthorizationServiceRBAC:
    """Tests for RBAC functionality."""

    def test_get_role_permissions(self, authz_service: AuthorizationService) -> None:
        """Verify role permission retrieval."""
        perms = authz_service.get_role_permissions(RoleClass.ADMIN)
        assert Permission.ADMIN_ACCESS in perms

    def test_get_all_permissions_from_roles(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify permission accumulation from roles."""
        perms = authz_service.get_all_permissions(admin_principal)
        assert Permission.ADMIN_ACCESS in perms
        assert Permission.VIEW_USERS in perms

    def test_get_all_permissions_includes_explicit(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify explicit permissions are included."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            explicit_permissions=frozenset(["view_deliveries"]),
        )
        perms = authz_service.get_all_permissions(principal)
        assert Permission.VIEW_DELIVERIES in perms

    def test_inactive_user_has_no_permissions(
        self,
        authz_service: AuthorizationService,
        inactive_principal: Principal,
    ) -> None:
        """Verify inactive users have no permissions."""
        perms = authz_service.get_all_permissions(inactive_principal)
        assert len(perms) == 0

    def test_has_permission_admin_access(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify admin has admin_access permission."""
        assert authz_service.has_permission(admin_principal, Permission.ADMIN_ACCESS)

    def test_has_permission_denied_for_missing_permission(
        self,
        authz_service: AuthorizationService,
        sender_principal: Principal,
    ) -> None:
        """Verify permission denied for unpermitted action."""
        # Sender should not have admin access
        assert not authz_service.has_permission(sender_principal, Permission.ADMIN_ACCESS)

    def test_has_permission_denied_for_inactive_user(
        self,
        authz_service: AuthorizationService,
        inactive_principal: Principal,
    ) -> None:
        """Verify inactive users are denied all permissions."""
        assert not authz_service.has_permission(inactive_principal, Permission.ADMIN_ACCESS)

    def test_superuser_bypasses_permission_check(
        self,
        authz_service: AuthorizationService,
        superuser_principal: Principal,
    ) -> None:
        """Verify superusers bypass normal permission checks."""
        # Superuser should have permissions they don't normally have
        assert authz_service.has_permission(superuser_principal, Permission.VERIFY_IDENTITY)

    def test_superuser_does_not_bypass_dual_control(
        self,
        authz_service: AuthorizationService,
        superuser_principal: Principal,
    ) -> None:
        """Verify superusers still need dual-control for sensitive ops."""
        # Superuser should NOT automatically have dual-control permissions
        assert not authz_service.has_permission(superuser_principal, Permission.KEY_MANAGEMENT)


class TestAuthorizationServiceRequirePermission:
    """Tests for require_permission method."""

    def test_require_permission_success(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify require_permission succeeds for permitted action."""
        # Should not raise
        authz_service.require_permission(admin_principal, Permission.ADMIN_ACCESS)

    def test_require_permission_raises_for_inactive(
        self,
        authz_service: AuthorizationService,
        inactive_principal: Principal,
    ) -> None:
        """Verify require_permission raises for inactive user."""
        with pytest.raises(InactiveAccountError):
            authz_service.require_permission(inactive_principal, Permission.ADMIN_ACCESS)

    def test_require_permission_raises_for_denied(
        self,
        authz_service: AuthorizationService,
        sender_principal: Principal,
    ) -> None:
        """Verify require_permission raises for denied permission."""
        with pytest.raises(PermissionDeniedError) as exc_info:
            authz_service.require_permission(sender_principal, Permission.ADMIN_ACCESS)
        assert exc_info.value.permission == Permission.ADMIN_ACCESS


# ---------------------------------------------------------------------------
# Tests: AuthorizationService - ABAC
# ---------------------------------------------------------------------------


class TestAuthorizationServiceABAC:
    """Tests for ABAC functionality."""

    def test_abac_allows_sender_own_delivery(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify sender can access their own delivery."""
        sender_id = uuid4()
        principal = Principal(
            principal_id=sender_id,
            principal_type="sender_user",
            roles=frozenset(["sender_user"]),
        )

        # Mock resource with sender ownership
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = sender_id
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert authz_service.has_permission(
            principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )

    def test_abac_allows_recipient_own_delivery(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify recipient can access delivery addressed to them."""
        recipient_id = uuid4()
        principal = Principal(
            principal_id=recipient_id,
            principal_type="recipient_user",
            roles=frozenset(["recipient_user"]),
        )

        # Mock resource with recipient ownership
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()
            recipient_party_id = recipient_id

        resource = MockDelivery()
        assert authz_service.has_permission(
            principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )

    def test_abac_denies_unrelated_delivery(
        self,
        authz_service: AuthorizationService,
        sender_principal: Principal,
    ) -> None:
        """Verify user cannot access unrelated delivery."""

        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()  # Different sender
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert not authz_service.has_permission(
            sender_principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )

    def test_abac_allows_assigned_delivery(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify user can access explicitly assigned delivery."""
        delivery_id = uuid4()
        principal = Principal(
            principal_id=uuid4(),
            principal_type="support",
            roles=frozenset(["support"]),
            abac_context=ABACContext(
                assigned_delivery_ids=frozenset([delivery_id]),
            ),
        )

        class MockDelivery:
            pass

        resource = MockDelivery()
        resource.delivery_id = delivery_id
        resource.sender_party_id = uuid4()
        resource.recipient_party_id = uuid4()

        assert authz_service.has_permission(
            principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )

    def test_abac_allows_admin_any_delivery(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify admins can access any delivery."""

        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert authz_service.has_permission(
            admin_principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )

    def test_abac_checks_organization_membership(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify organization membership is checked."""
        org_id = uuid4()
        principal = Principal(
            principal_id=uuid4(),
            principal_type="sender_user",
            roles=frozenset(["sender_user"]),
            abac_context=ABACContext(
                organization_ids=frozenset([org_id]),
            ),
        )

        class MockResource:
            organization_id = org_id

        resource = MockResource()
        # Note: sender_user has VIEW_DELIVERIES permission
        assert authz_service.has_permission(
            principal,
            Permission.VIEW_DELIVERIES,
            resource,
        )


# ---------------------------------------------------------------------------
# Tests: Dual-control workflow
# ---------------------------------------------------------------------------


class TestDualControlWorkflow:
    """Tests for dual-control approval workflow."""

    def test_requires_dual_control(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify dual-control permission identification."""
        assert authz_service.requires_dual_control(Permission.KEY_MANAGEMENT)
        assert not authz_service.requires_dual_control(Permission.VIEW_DELIVERIES)

    def test_create_dual_control_request(
        self,
        authz_service: AuthorizationService,
        security_officer_principal: Principal,
    ) -> None:
        """Verify dual-control request creation."""
        request = authz_service.create_dual_control_request(
            principal=security_officer_principal,
            permission=Permission.KEY_MANAGEMENT,
            operation="Generate new HSM key",
            reason="Annual key rotation",
            parameters={"key_type": "RSA-4096"},
        )

        assert request.is_pending
        assert not request.is_approved
        assert not request.is_rejected
        assert request.permission == Permission.KEY_MANAGEMENT
        assert request.requested_by == security_officer_principal.principal_id
        assert request.parameters["key_type"] == "RSA-4096"

    def test_create_dual_control_request_denied_without_permission(
        self,
        authz_service: AuthorizationService,
        sender_principal: Principal,
    ) -> None:
        """Verify request creation denied without base permission."""
        with pytest.raises(PermissionDeniedError):
            authz_service.create_dual_control_request(
                principal=sender_principal,
                permission=Permission.KEY_MANAGEMENT,
                operation="Generate new HSM key",
                reason="Testing",
            )

    def test_approve_dual_control_request(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify dual-control request approval."""
        # Create two different security officers
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        approver = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        # Create request
        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Scheduled maintenance",
        )

        # Approve
        approved_request = authz_service.approve_dual_control_request(
            request.request_id,
            approver,
        )

        assert approved_request.is_approved
        assert approved_request.approved_by == approver.principal_id

    def test_approve_dual_control_self_approval_denied(
        self,
        authz_service: AuthorizationService,
        security_officer_principal: Principal,
    ) -> None:
        """Verify self-approval is denied (separation of duties)."""
        request = authz_service.create_dual_control_request(
            principal=security_officer_principal,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        with pytest.raises(SeparationOfDutiesError):
            authz_service.approve_dual_control_request(
                request.request_id,
                security_officer_principal,  # Same person trying to approve
            )

    def test_approve_dual_control_without_permission_denied(
        self,
        authz_service: AuthorizationService,
        security_officer_principal: Principal,
        sender_principal: Principal,
    ) -> None:
        """Verify approval denied without proper permission."""
        request = authz_service.create_dual_control_request(
            principal=security_officer_principal,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        with pytest.raises(PermissionDeniedError):
            authz_service.approve_dual_control_request(
                request.request_id,
                sender_principal,  # Doesn't have key_management permission
            )

    def test_reject_dual_control_request(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify dual-control request rejection."""
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        rejector = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        rejected_request = authz_service.reject_dual_control_request(
            request.request_id,
            rejector,
            "Not approved by security review",
        )

        assert rejected_request.is_rejected
        assert rejected_request.rejected_by == rejector.principal_id
        assert rejected_request.rejection_reason == "Not approved by security review"

    def test_check_dual_control_approved(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify approval status check."""
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        approver = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        # Not approved yet
        assert not authz_service.check_dual_control_approved(request.request_id)

        # Approve
        authz_service.approve_dual_control_request(request.request_id, approver)

        # Now approved
        assert authz_service.check_dual_control_approved(request.request_id)

    def test_cannot_approve_already_processed_request(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify cannot approve an already processed request."""
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        approver1 = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        approver2 = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        # First approval succeeds
        authz_service.approve_dual_control_request(request.request_id, approver1)

        # Second approval should fail
        with pytest.raises(ValueError, match="already been processed"):
            authz_service.approve_dual_control_request(request.request_id, approver2)


class TestDualControlRequest:
    """Tests for DualControlRequest dataclass."""

    def test_is_pending(self) -> None:
        """Verify pending state detection."""
        request = DualControlRequest(
            request_id=uuid4(),
            operation="test",
            permission=Permission.KEY_MANAGEMENT,
            requested_by=uuid4(),
            requested_at=datetime.now(UTC),
            reason="test",
        )
        assert request.is_pending
        assert not request.is_approved
        assert not request.is_rejected

    def test_is_expired(self) -> None:
        """Verify expiry detection."""
        past = datetime.now(UTC) - timedelta(hours=1)
        request = DualControlRequest(
            request_id=uuid4(),
            operation="test",
            permission=Permission.KEY_MANAGEMENT,
            requested_by=uuid4(),
            requested_at=datetime.now(UTC),
            reason="test",
            expires_at=past,
        )
        assert request.is_expired


# ---------------------------------------------------------------------------
# Tests: Separation of duties
# ---------------------------------------------------------------------------


class TestSeparationOfDuties:
    """Tests for separation of duties enforcement."""

    def test_admin_cannot_be_auditor(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify admin cannot also be auditor."""
        can_add = authz_service.check_separation_of_duties(
            admin_principal,
            RoleClass.AUDITOR,
        )
        assert not can_add

    def test_auditor_cannot_be_admin(
        self,
        authz_service: AuthorizationService,
        auditor_principal: Principal,
    ) -> None:
        """Verify auditor cannot also be admin."""
        can_add = authz_service.check_separation_of_duties(
            auditor_principal,
            RoleClass.ADMIN,
        )
        assert not can_add

    def test_security_officer_cannot_be_admin(
        self,
        authz_service: AuthorizationService,
        security_officer_principal: Principal,
    ) -> None:
        """Verify security officer cannot also be admin."""
        can_add = authz_service.check_separation_of_duties(
            security_officer_principal,
            RoleClass.ADMIN,
        )
        assert not can_add

    def test_admin_cannot_be_security_officer(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify admin cannot also be security officer."""
        can_add = authz_service.check_separation_of_duties(
            admin_principal,
            RoleClass.SECURITY_OFFICER,
        )
        assert not can_add

    def test_registration_officer_cannot_be_sender(
        self,
        authz_service: AuthorizationService,
    ) -> None:
        """Verify registration officer cannot be a sender user."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["registration_officer"]),
        )
        can_add = authz_service.check_separation_of_duties(
            principal,
            RoleClass.SENDER_USER,
        )
        assert not can_add

    def test_compatible_roles_allowed(
        self,
        authz_service: AuthorizationService,
        admin_principal: Principal,
    ) -> None:
        """Verify compatible roles can be combined."""
        # Admin can also have support role
        can_add = authz_service.check_separation_of_duties(
            admin_principal,
            RoleClass.SUPPORT,
        )
        assert can_add


# ---------------------------------------------------------------------------
# Tests: require_permission decorator
# ---------------------------------------------------------------------------


class TestRequirePermissionDecorator:
    """Tests for the require_permission decorator."""

    def test_decorator_allows_permitted_action(self) -> None:
        """Verify decorator allows execution when permission granted."""
        admin = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=True,
        )

        @require_permission_decorator(
            Permission.ADMIN_ACCESS,
            get_principal=lambda: admin,
        )
        def protected_action() -> str:
            return "success"

        result = protected_action()
        assert result == "success"

    def test_decorator_denies_unpermitted_action(self) -> None:
        """Verify decorator raises when permission denied."""
        sender = Principal(
            principal_id=uuid4(),
            principal_type="sender_user",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        @require_permission_decorator(
            Permission.ADMIN_ACCESS,
            get_principal=lambda: sender,
        )
        def protected_action() -> str:
            return "success"

        with pytest.raises(PermissionDeniedError):
            protected_action()

    def test_decorator_requires_dual_control(self) -> None:
        """Verify decorator raises for dual-control operations."""
        security_officer = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        @require_permission_decorator(
            Permission.KEY_MANAGEMENT,
            get_principal=lambda: security_officer,
        )
        def sensitive_action() -> str:
            return "success"

        with pytest.raises(DualControlRequiredError):
            sensitive_action()

    @pytest.mark.asyncio
    async def test_decorator_with_async_function(self) -> None:
        """Verify decorator works with async functions."""
        admin = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=True,
        )

        @require_permission_decorator(
            Permission.ADMIN_ACCESS,
            get_principal=lambda: admin,
        )
        async def async_protected_action() -> str:
            return "async_success"

        result = await async_protected_action()
        assert result == "async_success"


# ---------------------------------------------------------------------------
# Tests: Authorization errors
# ---------------------------------------------------------------------------


class TestAuthorizationErrors:
    """Tests for authorization error classes."""

    def test_permission_denied_error(self) -> None:
        """Verify PermissionDeniedError carries permission info."""
        error = PermissionDeniedError(
            "Access denied",
            permission=Permission.ADMIN_ACCESS,
        )
        assert error.permission == Permission.ADMIN_ACCESS
        assert "Access denied" in str(error)

    def test_dual_control_required_error(self) -> None:
        """Verify DualControlRequiredError carries request ID."""
        request_id = uuid4()
        error = DualControlRequiredError(
            "Dual control required",
            permission=Permission.KEY_MANAGEMENT,
            request_id=request_id,
        )
        assert error.permission == Permission.KEY_MANAGEMENT
        assert error.request_id == request_id

    def test_inactive_account_error(self) -> None:
        """Verify InactiveAccountError is an AuthorizationError."""
        error = InactiveAccountError("Account inactive")
        assert isinstance(error, AuthorizationError)

    def test_separation_of_duties_error(self) -> None:
        """Verify SeparationOfDutiesError is an AuthorizationError."""
        error = SeparationOfDutiesError(
            "Cannot combine roles",
            permission=Permission.ADMIN_ACCESS,
        )
        assert isinstance(error, AuthorizationError)
