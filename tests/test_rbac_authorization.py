"""Tests for RBAC/authorization system integration.

Tests cover:
- Role-based access control for all role types
- Permission checking for protected endpoints
- Separation of duties enforcement
- Admin action logging integration
- Unauthorized access rejection (401/403 responses)
- Security event logging for authorization decisions

Beads Task: qerds-wla

Run with: docker compose exec qerds-api pytest tests/test_rbac_authorization.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException, Request, status

from qerds.api.middleware.auth import (
    AuthenticatedUser,
    get_current_user,
    optional_authenticated_user,
    require_admin_user,
    require_authenticated_user,
    require_permission,
    require_role,
    require_superuser,
    set_current_user,
)
from qerds.services.authz import (
    DUAL_CONTROL_PERMISSIONS,
    ROLE_PERMISSIONS,
    ABACContext,
    AccessPurpose,
    AuthorizationService,
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
# Fixtures for all role types
# ---------------------------------------------------------------------------


@pytest.fixture
def sender_user() -> AuthenticatedUser:
    """Create a sender user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["sender_user"]),
        permissions=frozenset(),
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def recipient_user() -> AuthenticatedUser:
    """Create a recipient user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["recipient_user"]),
        permissions=frozenset(),
        ip_address="192.168.1.101",
        user_agent="Mozilla/5.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def admin_user() -> AuthenticatedUser:
    """Create an admin user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["admin"]),
        permissions=frozenset(),
        ip_address="10.0.0.1",
        user_agent="AdminClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def super_admin_user() -> AuthenticatedUser:
    """Create a superuser admin for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=True,
        is_active=True,
        roles=frozenset(["admin"]),
        permissions=frozenset(),
        ip_address="10.0.0.2",
        user_agent="AdminClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def security_officer_user() -> AuthenticatedUser:
    """Create a security officer user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["security_officer"]),
        permissions=frozenset(),
        ip_address="10.0.0.3",
        user_agent="SecurityClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def auditor_user() -> AuthenticatedUser:
    """Create an auditor user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["auditor"]),
        permissions=frozenset(),
        ip_address="10.0.0.4",
        user_agent="AuditClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def inactive_user() -> AuthenticatedUser:
    """Create an inactive user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=False,
        roles=frozenset(["admin"]),
        permissions=frozenset(),
        ip_address="10.0.0.5",
        user_agent="Client/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def api_client_user() -> AuthenticatedUser:
    """Create an API client user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="api_client",
        session_id=None,
        is_superuser=False,
        is_active=True,
        roles=frozenset(["api_client"]),
        permissions=frozenset(["create_delivery", "view_deliveries"]),
        ip_address="203.0.113.100",
        user_agent="APIClient/2.0",
        auth_method="api_key",
        metadata={"client_id": "test-client"},
    )


@pytest.fixture
def support_user() -> AuthenticatedUser:
    """Create a support user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["support"]),
        permissions=frozenset(),
        ip_address="10.0.0.6",
        user_agent="SupportClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def registration_officer_user() -> AuthenticatedUser:
    """Create a registration officer user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["registration_officer"]),
        permissions=frozenset(),
        ip_address="10.0.0.7",
        user_agent="RegistrationClient/1.0",
        auth_method="session",
        metadata={},
    )


# ---------------------------------------------------------------------------
# Tests: AuthenticatedUser methods
# ---------------------------------------------------------------------------


class TestAuthenticatedUserPermissions:
    """Tests for AuthenticatedUser permission and role checking."""

    def test_has_permission_with_explicit_permission(self) -> None:
        """User with explicit permission has access."""
        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="api_client",
            permissions=frozenset(["view_deliveries", "create_delivery"]),
        )
        assert user.has_permission("view_deliveries")
        assert user.has_permission("create_delivery")
        assert not user.has_permission("admin_access")

    def test_has_permission_superuser_bypass(self) -> None:
        """Superuser has all permissions."""
        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="admin_user",
            is_superuser=True,
            permissions=frozenset(),
        )
        # Superuser has any permission
        assert user.has_permission("admin_access")
        assert user.has_permission("view_deliveries")
        assert user.has_permission("nonexistent_permission")

    def test_has_role_checks_role_membership(self) -> None:
        """has_role correctly checks role membership."""
        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "support"]),
        )
        assert user.has_role("admin")
        assert user.has_role("support")
        assert not user.has_role("auditor")

    def test_to_principal_conversion(self, admin_user: AuthenticatedUser) -> None:
        """AuthenticatedUser converts to Principal correctly."""
        principal = admin_user.to_principal()

        assert principal.principal_id == admin_user.principal_id
        assert principal.principal_type == admin_user.principal_type
        assert principal.roles == admin_user.roles
        assert principal.is_superuser == admin_user.is_superuser
        assert principal.is_active == admin_user.is_active
        assert principal.abac_context.ip_address == admin_user.ip_address
        assert principal.abac_context.user_agent == admin_user.user_agent


# ---------------------------------------------------------------------------
# Tests: Role permissions for each role type
# ---------------------------------------------------------------------------


class TestSenderUserPermissions:
    """Tests for sender user permissions."""

    def test_sender_can_create_delivery(self) -> None:
        """Sender has create_delivery permission."""
        perms = ROLE_PERMISSIONS[RoleClass.SENDER_USER]
        assert Permission.CREATE_DELIVERY in perms

    def test_sender_can_view_deliveries(self) -> None:
        """Sender can view their own deliveries."""
        perms = ROLE_PERMISSIONS[RoleClass.SENDER_USER]
        assert Permission.VIEW_DELIVERIES in perms

    def test_sender_can_upload_content(self) -> None:
        """Sender can upload content."""
        perms = ROLE_PERMISSIONS[RoleClass.SENDER_USER]
        assert Permission.UPLOAD_CONTENT in perms

    def test_sender_cannot_access_admin(self) -> None:
        """Sender cannot access admin functions."""
        perms = ROLE_PERMISSIONS[RoleClass.SENDER_USER]
        assert Permission.ADMIN_ACCESS not in perms
        assert Permission.MANAGE_USERS not in perms

    def test_sender_cannot_accept_delivery(self) -> None:
        """Sender cannot accept deliveries (recipient function)."""
        perms = ROLE_PERMISSIONS[RoleClass.SENDER_USER]
        assert Permission.ACCEPT_DELIVERY not in perms


class TestRecipientUserPermissions:
    """Tests for recipient user permissions."""

    def test_recipient_can_accept_delivery(self) -> None:
        """Recipient can accept deliveries."""
        perms = ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.ACCEPT_DELIVERY in perms

    def test_recipient_can_refuse_delivery(self) -> None:
        """Recipient can refuse deliveries."""
        perms = ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.REFUSE_DELIVERY in perms

    def test_recipient_can_view_deliveries(self) -> None:
        """Recipient can view deliveries addressed to them."""
        perms = ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.VIEW_DELIVERIES in perms

    def test_recipient_cannot_create_delivery(self) -> None:
        """Recipient cannot create deliveries."""
        perms = ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.CREATE_DELIVERY not in perms

    def test_recipient_cannot_access_admin(self) -> None:
        """Recipient cannot access admin functions."""
        perms = ROLE_PERMISSIONS[RoleClass.RECIPIENT_USER]
        assert Permission.ADMIN_ACCESS not in perms


class TestAdminUserPermissions:
    """Tests for admin user permissions."""

    def test_admin_has_admin_access(self) -> None:
        """Admin has admin_access permission."""
        perms = ROLE_PERMISSIONS[RoleClass.ADMIN]
        assert Permission.ADMIN_ACCESS in perms

    def test_admin_can_manage_users(self) -> None:
        """Admin can manage users."""
        perms = ROLE_PERMISSIONS[RoleClass.ADMIN]
        assert Permission.VIEW_USERS in perms
        assert Permission.MANAGE_USERS in perms

    def test_admin_can_manage_roles(self) -> None:
        """Admin can manage roles."""
        perms = ROLE_PERMISSIONS[RoleClass.ADMIN]
        assert Permission.VIEW_ROLES in perms
        assert Permission.MANAGE_ROLES in perms

    def test_admin_cannot_manage_keys_without_dual_control(self) -> None:
        """Admin cannot manage keys directly (requires dual-control)."""
        perms = ROLE_PERMISSIONS[RoleClass.ADMIN]
        assert Permission.KEY_MANAGEMENT not in perms


class TestSecurityOfficerPermissions:
    """Tests for security officer permissions."""

    def test_security_officer_has_key_management(self) -> None:
        """Security officer has key management permission."""
        perms = ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]
        assert Permission.KEY_MANAGEMENT in perms

    def test_security_officer_has_config_change(self) -> None:
        """Security officer can change config."""
        perms = ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]
        assert Permission.CONFIG_CHANGE in perms

    def test_security_officer_can_export_audit_logs(self) -> None:
        """Security officer can export audit logs."""
        perms = ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]
        assert Permission.EXPORT_AUDIT_LOGS in perms

    def test_security_officer_cannot_manage_users(self) -> None:
        """Security officer cannot directly manage users."""
        perms = ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]
        assert Permission.MANAGE_USERS not in perms


class TestAuditorPermissions:
    """Tests for auditor permissions."""

    def test_auditor_has_audit_access(self) -> None:
        """Auditor has audit access permission."""
        perms = ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.AUDIT_ACCESS in perms

    def test_auditor_can_view_audit_logs(self) -> None:
        """Auditor can view audit logs."""
        perms = ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.VIEW_AUDIT_LOGS in perms

    def test_auditor_can_export_evidence(self) -> None:
        """Auditor can export evidence."""
        perms = ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.EXPORT_EVIDENCE in perms

    def test_auditor_cannot_modify_users(self) -> None:
        """Auditor cannot modify users (read-only access)."""
        perms = ROLE_PERMISSIONS[RoleClass.AUDITOR]
        assert Permission.MANAGE_USERS not in perms


class TestSupportUserPermissions:
    """Tests for support user permissions."""

    def test_support_can_view_support_cases(self) -> None:
        """Support can view support cases."""
        perms = ROLE_PERMISSIONS[RoleClass.SUPPORT]
        assert Permission.VIEW_SUPPORT_CASES in perms

    def test_support_can_manage_support_cases(self) -> None:
        """Support can manage support cases."""
        perms = ROLE_PERMISSIONS[RoleClass.SUPPORT]
        assert Permission.MANAGE_SUPPORT_CASES in perms

    def test_support_can_view_deliveries(self) -> None:
        """Support can view deliveries for support purposes."""
        perms = ROLE_PERMISSIONS[RoleClass.SUPPORT]
        assert Permission.VIEW_DELIVERIES in perms


class TestRegistrationOfficerPermissions:
    """Tests for registration officer permissions."""

    def test_registration_officer_can_verify_identity(self) -> None:
        """Registration officer can verify identities."""
        perms = ROLE_PERMISSIONS[RoleClass.REGISTRATION_OFFICER]
        assert Permission.VERIFY_IDENTITY in perms

    def test_registration_officer_can_manage_proofs(self) -> None:
        """Registration officer can manage identity proofs."""
        perms = ROLE_PERMISSIONS[RoleClass.REGISTRATION_OFFICER]
        assert Permission.MANAGE_IDENTITY_PROOFS in perms


class TestApiClientPermissions:
    """Tests for API client permissions."""

    def test_api_client_has_minimal_permissions(self) -> None:
        """API client has minimal default permissions."""
        perms = ROLE_PERMISSIONS[RoleClass.API_CLIENT]
        assert Permission.CREATE_DELIVERY in perms
        assert Permission.VIEW_DELIVERIES in perms

    def test_api_client_cannot_access_admin(self) -> None:
        """API client cannot access admin functions by default."""
        perms = ROLE_PERMISSIONS[RoleClass.API_CLIENT]
        assert Permission.ADMIN_ACCESS not in perms


# ---------------------------------------------------------------------------
# Tests: Authorization service with different roles
# ---------------------------------------------------------------------------


class TestAuthorizationServiceRoleIntegration:
    """Integration tests for authorization service with all role types."""

    @pytest.fixture
    def authz_service(self) -> AuthorizationService:
        """Create authorization service instance."""
        return AuthorizationService()

    def test_sender_principal_permissions(self, authz_service: AuthorizationService) -> None:
        """Sender principal has correct permissions."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        assert authz_service.has_permission(principal, Permission.CREATE_DELIVERY)
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES)
        assert not authz_service.has_permission(principal, Permission.ADMIN_ACCESS)
        assert not authz_service.has_permission(principal, Permission.ACCEPT_DELIVERY)

    def test_recipient_principal_permissions(self, authz_service: AuthorizationService) -> None:
        """Recipient principal has correct permissions."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["recipient_user"]),
            is_active=True,
        )

        assert authz_service.has_permission(principal, Permission.ACCEPT_DELIVERY)
        assert authz_service.has_permission(principal, Permission.REFUSE_DELIVERY)
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES)
        assert not authz_service.has_permission(principal, Permission.CREATE_DELIVERY)

    def test_admin_principal_permissions(self, authz_service: AuthorizationService) -> None:
        """Admin principal has correct permissions."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=True,
        )

        assert authz_service.has_permission(principal, Permission.ADMIN_ACCESS)
        assert authz_service.has_permission(principal, Permission.VIEW_USERS)
        assert authz_service.has_permission(principal, Permission.MANAGE_USERS)
        # Key management requires security_officer role
        assert not authz_service.has_permission(principal, Permission.KEY_MANAGEMENT)

    def test_superuser_principal_bypass(self, authz_service: AuthorizationService) -> None:
        """Superuser bypasses permission checks except dual-control."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_superuser=True,
            is_active=True,
        )

        # Superuser has all non-dual-control permissions
        assert authz_service.has_permission(principal, Permission.ADMIN_ACCESS)
        assert authz_service.has_permission(principal, Permission.VERIFY_IDENTITY)
        assert authz_service.has_permission(principal, Permission.VIEW_SUPPORT_CASES)

        # But NOT dual-control permissions
        assert not authz_service.has_permission(principal, Permission.KEY_MANAGEMENT)
        assert not authz_service.has_permission(principal, Permission.CONFIG_CHANGE)

    def test_inactive_principal_no_permissions(self, authz_service: AuthorizationService) -> None:
        """Inactive principal has no permissions."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=False,
        )

        assert not authz_service.has_permission(principal, Permission.ADMIN_ACCESS)
        assert not authz_service.has_permission(principal, Permission.VIEW_USERS)


# ---------------------------------------------------------------------------
# Tests: Separation of duties
# ---------------------------------------------------------------------------


class TestSeparationOfDutiesEnforcement:
    """Tests for separation of duties enforcement."""

    @pytest.fixture
    def authz_service(self) -> AuthorizationService:
        """Create authorization service instance."""
        return AuthorizationService()

    def test_admin_cannot_be_auditor(self, authz_service: AuthorizationService) -> None:
        """Admin role cannot be combined with auditor role."""
        admin_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
        )

        assert not authz_service.check_separation_of_duties(admin_principal, RoleClass.AUDITOR)

    def test_auditor_cannot_be_admin(self, authz_service: AuthorizationService) -> None:
        """Auditor role cannot be combined with admin role."""
        auditor_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["auditor"]),
        )

        assert not authz_service.check_separation_of_duties(auditor_principal, RoleClass.ADMIN)

    def test_security_officer_cannot_be_admin(self, authz_service: AuthorizationService) -> None:
        """Security officer role cannot be combined with admin role."""
        security_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
        )

        assert not authz_service.check_separation_of_duties(security_principal, RoleClass.ADMIN)

    def test_admin_cannot_be_security_officer(self, authz_service: AuthorizationService) -> None:
        """Admin role cannot be combined with security officer role."""
        admin_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
        )

        can_add = authz_service.check_separation_of_duties(
            admin_principal, RoleClass.SECURITY_OFFICER
        )
        assert not can_add

    def test_registration_officer_cannot_be_sender(
        self, authz_service: AuthorizationService
    ) -> None:
        """Registration officer cannot also be a sender user."""
        reg_officer = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["registration_officer"]),
        )

        assert not authz_service.check_separation_of_duties(reg_officer, RoleClass.SENDER_USER)

    def test_registration_officer_cannot_be_recipient(
        self, authz_service: AuthorizationService
    ) -> None:
        """Registration officer cannot also be a recipient user."""
        reg_officer = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["registration_officer"]),
        )

        assert not authz_service.check_separation_of_duties(reg_officer, RoleClass.RECIPIENT_USER)

    def test_compatible_roles_allowed(self, authz_service: AuthorizationService) -> None:
        """Compatible roles can be combined."""
        admin_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
        )

        # Admin can also have support role
        assert authz_service.check_separation_of_duties(admin_principal, RoleClass.SUPPORT)

    def test_multiple_incompatible_roles_prevented(
        self, authz_service: AuthorizationService
    ) -> None:
        """User with one incompatible role cannot gain another."""
        # User who is both admin and support
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "support"]),
        )

        # Still cannot become auditor (incompatible with admin)
        assert not authz_service.check_separation_of_duties(principal, RoleClass.AUDITOR)


# ---------------------------------------------------------------------------
# Tests: Dual-control workflow
# ---------------------------------------------------------------------------


class TestDualControlWorkflowIntegration:
    """Integration tests for dual-control workflow."""

    @pytest.fixture
    def authz_service(self) -> AuthorizationService:
        """Create authorization service instance."""
        return AuthorizationService()

    def test_key_management_requires_dual_control(
        self, authz_service: AuthorizationService
    ) -> None:
        """Key management permission requires dual-control."""
        assert authz_service.requires_dual_control(Permission.KEY_MANAGEMENT)

    def test_config_change_requires_dual_control(self, authz_service: AuthorizationService) -> None:
        """Config change permission requires dual-control."""
        assert authz_service.requires_dual_control(Permission.CONFIG_CHANGE)

    def test_export_audit_logs_requires_dual_control(
        self, authz_service: AuthorizationService
    ) -> None:
        """Export audit logs requires dual-control."""
        assert authz_service.requires_dual_control(Permission.EXPORT_AUDIT_LOGS)

    def test_view_deliveries_no_dual_control(self, authz_service: AuthorizationService) -> None:
        """Normal permissions don't require dual-control."""
        assert not authz_service.requires_dual_control(Permission.VIEW_DELIVERIES)
        assert not authz_service.requires_dual_control(Permission.ADMIN_ACCESS)

    def test_dual_control_workflow_complete(self, authz_service: AuthorizationService) -> None:
        """Complete dual-control workflow: request, approve, verify."""
        # Create two security officers
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
            operation="Generate signing key",
            reason="Annual key rotation as per security policy",
            parameters={"key_type": "EC-P384", "purpose": "signing"},
        )

        assert request.is_pending
        assert not request.is_approved
        assert request.requested_by == requester.principal_id

        # Verify not approved yet
        assert not authz_service.check_dual_control_approved(request.request_id)

        # Approve with different user
        approved_request = authz_service.approve_dual_control_request(request.request_id, approver)

        assert approved_request.is_approved
        assert approved_request.approved_by == approver.principal_id
        assert authz_service.check_dual_control_approved(request.request_id)

    def test_self_approval_rejected(self, authz_service: AuthorizationService) -> None:
        """Self-approval of dual-control requests is rejected."""
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )

        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Scheduled maintenance",
        )

        with pytest.raises(SeparationOfDutiesError, match="Cannot approve own"):
            authz_service.approve_dual_control_request(request.request_id, requester)

    def test_unprivileged_user_cannot_request(self, authz_service: AuthorizationService) -> None:
        """User without permission cannot create dual-control request."""
        sender = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        with pytest.raises(PermissionDeniedError):
            authz_service.create_dual_control_request(
                principal=sender,
                permission=Permission.KEY_MANAGEMENT,
                operation="Key rotation",
                reason="Testing",
            )

    def test_unprivileged_user_cannot_approve(self, authz_service: AuthorizationService) -> None:
        """User without permission cannot approve dual-control request."""
        requester = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
            is_active=True,
        )
        unprivileged = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        request = authz_service.create_dual_control_request(
            principal=requester,
            permission=Permission.KEY_MANAGEMENT,
            operation="Key rotation",
            reason="Testing",
        )

        with pytest.raises(PermissionDeniedError):
            authz_service.approve_dual_control_request(request.request_id, unprivileged)


# ---------------------------------------------------------------------------
# Tests: FastAPI auth dependencies
# ---------------------------------------------------------------------------


class TestFastAPIAuthDependencies:
    """Tests for FastAPI authentication dependencies."""

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create a mock request object."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        return request

    @pytest.mark.asyncio
    async def test_require_authenticated_user_success(
        self, admin_user: AuthenticatedUser, mock_request: Request
    ) -> None:
        """require_authenticated_user returns user when authenticated."""
        set_current_user(admin_user)
        try:
            result = await require_authenticated_user(mock_request)
            assert result == admin_user
        finally:
            set_current_user(None)

    @pytest.mark.asyncio
    async def test_require_authenticated_user_from_request_state(
        self, admin_user: AuthenticatedUser, mock_request: Request
    ) -> None:
        """require_authenticated_user falls back to request.state.user."""
        set_current_user(None)
        mock_request.state.user = admin_user

        result = await require_authenticated_user(mock_request)
        assert result == admin_user

    @pytest.mark.asyncio
    async def test_require_authenticated_user_401_when_missing(self, mock_request: Request) -> None:
        """require_authenticated_user raises 401 when no user."""
        set_current_user(None)
        mock_request.state = MagicMock(spec=[])  # No user attribute

        with pytest.raises(HTTPException) as exc_info:
            await require_authenticated_user(mock_request)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_require_authenticated_user_403_when_inactive(
        self, inactive_user: AuthenticatedUser, mock_request: Request
    ) -> None:
        """require_authenticated_user raises 403 when user is inactive."""
        set_current_user(inactive_user)
        try:
            with pytest.raises(HTTPException) as exc_info:
                await require_authenticated_user(mock_request)

            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
            assert "inactive" in exc_info.value.detail.lower()
        finally:
            set_current_user(None)

    @pytest.mark.asyncio
    async def test_require_admin_user_success(self, admin_user: AuthenticatedUser) -> None:
        """require_admin_user returns user when admin."""
        result = await require_admin_user(admin_user)
        assert result == admin_user

    @pytest.mark.asyncio
    async def test_require_admin_user_403_when_not_admin(
        self, sender_user: AuthenticatedUser
    ) -> None:
        """require_admin_user raises 403 when user is not admin."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_user(sender_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_superuser_success(self, super_admin_user: AuthenticatedUser) -> None:
        """require_superuser returns user when superuser."""
        result = await require_superuser(super_admin_user)
        assert result == super_admin_user

    @pytest.mark.asyncio
    async def test_require_superuser_403_when_not_super(
        self, admin_user: AuthenticatedUser
    ) -> None:
        """require_superuser raises 403 when user is not superuser."""
        with pytest.raises(HTTPException) as exc_info:
            await require_superuser(admin_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


class TestRequirePermissionDependency:
    """Tests for the require_permission dependency factory."""

    @pytest.mark.asyncio
    async def test_require_permission_success(self, admin_user: AuthenticatedUser) -> None:
        """Permission check passes when user has permission."""
        # Admin has admin_access via role
        admin_user_with_perms = AuthenticatedUser(
            principal_id=admin_user.principal_id,
            principal_type="admin_user",
            is_active=True,
            roles=frozenset(["admin"]),
            permissions=frozenset(["admin_access"]),
        )

        check_perm = require_permission("admin_access")
        result = await check_perm(admin_user_with_perms)
        assert result == admin_user_with_perms

    @pytest.mark.asyncio
    async def test_require_permission_403_when_missing(
        self, sender_user: AuthenticatedUser
    ) -> None:
        """Permission check fails when user lacks permission."""
        check_perm = require_permission("admin_access")

        with pytest.raises(HTTPException) as exc_info:
            await check_perm(sender_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin_access" in exc_info.value.detail


class TestRequireRoleDependency:
    """Tests for the require_role dependency factory."""

    @pytest.mark.asyncio
    async def test_require_role_success(self, admin_user: AuthenticatedUser) -> None:
        """Role check passes when user has role."""
        check_role = require_role("admin")
        result = await check_role(admin_user)
        assert result == admin_user

    @pytest.mark.asyncio
    async def test_require_role_403_when_missing(self, sender_user: AuthenticatedUser) -> None:
        """Role check fails when user lacks role."""
        check_role = require_role("admin")

        with pytest.raises(HTTPException) as exc_info:
            await check_role(sender_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin" in exc_info.value.detail


class TestOptionalAuthenticatedUser:
    """Tests for optional_authenticated_user dependency."""

    @pytest.fixture
    def mock_request(self) -> Request:
        """Create mock request."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        return request

    @pytest.mark.asyncio
    async def test_returns_user_when_authenticated(
        self, admin_user: AuthenticatedUser, mock_request: Request
    ) -> None:
        """Returns user when authenticated."""
        set_current_user(admin_user)
        try:
            result = await optional_authenticated_user(mock_request)
            assert result == admin_user
        finally:
            set_current_user(None)

    @pytest.mark.asyncio
    async def test_returns_none_when_not_authenticated(self, mock_request: Request) -> None:
        """Returns None when not authenticated."""
        set_current_user(None)
        mock_request.state = MagicMock(spec=[])

        result = await optional_authenticated_user(mock_request)
        assert result is None


# ---------------------------------------------------------------------------
# Tests: ABAC resource-based authorization
# ---------------------------------------------------------------------------


class TestABACResourceAuthorization:
    """Tests for attribute-based access control on resources."""

    @pytest.fixture
    def authz_service(self) -> AuthorizationService:
        """Create authorization service instance."""
        return AuthorizationService()

    def test_sender_can_access_own_delivery(self, authz_service: AuthorizationService) -> None:
        """Sender can access deliveries they created."""
        sender_id = uuid4()
        principal = Principal(
            principal_id=sender_id,
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        # Mock delivery owned by sender
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = sender_id
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_sender_cannot_access_others_delivery(
        self, authz_service: AuthorizationService
    ) -> None:
        """Sender cannot access deliveries they didn't create."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        # Mock delivery owned by different sender
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()  # Different user
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert not authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_recipient_can_access_addressed_delivery(
        self, authz_service: AuthorizationService
    ) -> None:
        """Recipient can access deliveries addressed to them."""
        recipient_id = uuid4()
        principal = Principal(
            principal_id=recipient_id,
            principal_type="party",
            roles=frozenset(["recipient_user"]),
            is_active=True,
        )

        # Mock delivery addressed to recipient
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()
            recipient_party_id = recipient_id

        resource = MockDelivery()
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_recipient_cannot_access_unaddressed_delivery(
        self, authz_service: AuthorizationService
    ) -> None:
        """Recipient cannot access deliveries not addressed to them."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["recipient_user"]),
            is_active=True,
        )

        # Mock delivery addressed to different recipient
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()
            recipient_party_id = uuid4()  # Different user

        resource = MockDelivery()
        assert not authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_admin_can_access_any_delivery(self, authz_service: AuthorizationService) -> None:
        """Admin can access any delivery."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=True,
        )

        # Mock delivery owned by someone else
        class MockDelivery:
            delivery_id = uuid4()
            sender_party_id = uuid4()
            recipient_party_id = uuid4()

        resource = MockDelivery()
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_support_user_with_assignment_can_access(
        self, authz_service: AuthorizationService
    ) -> None:
        """Support user with explicit assignment can access delivery."""
        delivery_id = uuid4()
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["support"]),
            is_active=True,
            abac_context=ABACContext(
                assigned_delivery_ids=frozenset([delivery_id]),
            ),
        )

        # Mock delivery (not owned by support user)
        class MockDelivery:
            pass

        resource = MockDelivery()
        resource.delivery_id = delivery_id
        resource.sender_party_id = uuid4()
        resource.recipient_party_id = uuid4()

        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)

    def test_organization_membership_grants_access(
        self, authz_service: AuthorizationService
    ) -> None:
        """Organization membership grants access to org resources."""
        org_id = uuid4()
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
            abac_context=ABACContext(
                organization_ids=frozenset([org_id]),
            ),
        )

        # Mock resource in same organization
        class MockResource:
            organization_id = org_id

        resource = MockResource()
        assert authz_service.has_permission(principal, Permission.VIEW_DELIVERIES, resource)


# ---------------------------------------------------------------------------
# Tests: Security event logging for authorization
# ---------------------------------------------------------------------------


class TestAuthorizationSecurityLogging:
    """Tests for security event logging in authorization decisions."""

    @pytest.mark.asyncio
    async def test_authz_granted_can_be_logged(self) -> None:
        """Authorization grant can be logged as security event."""
        from qerds.services.security_events import (
            AuthzOutcome,
            SecurityActor,
            SecurityEventPayload,
            SecurityEventType,
        )

        actor = SecurityActor(
            actor_id=str(uuid4()),
            actor_type="admin_user",
            ip_address="10.0.0.1",
            session_id=str(uuid4()),
        )

        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTHZ_GRANTED,
            actor=actor,
            action="view_delivery",
            resource_type="delivery",
            resource_id=str(uuid4()),
            outcome=AuthzOutcome.GRANTED.value,
        )

        payload_dict = payload.to_dict()
        assert payload_dict["event_type"] == "authz_granted"
        assert payload_dict["actor"]["actor_type"] == "admin_user"
        assert payload_dict["outcome"] == "granted"

    @pytest.mark.asyncio
    async def test_authz_denied_can_be_logged(self) -> None:
        """Authorization denial can be logged as security event."""
        from qerds.services.security_events import (
            AuthzOutcome,
            SecurityActor,
            SecurityEventPayload,
            SecurityEventType,
        )

        actor = SecurityActor(
            actor_id=str(uuid4()),
            actor_type="party",
            ip_address="192.168.1.100",
        )

        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTHZ_DENIED,
            actor=actor,
            action="admin_access",
            resource_type="admin_panel",
            outcome=AuthzOutcome.DENIED.value,
            details={"reason": "insufficient_role"},
        )

        payload_dict = payload.to_dict()
        assert payload_dict["event_type"] == "authz_denied"
        assert payload_dict["outcome"] == "denied"
        assert payload_dict["details"]["reason"] == "insufficient_role"

    @pytest.mark.asyncio
    async def test_admin_action_logging(self, admin_user: AuthenticatedUser) -> None:
        """Admin actions are logged with proper actor info."""
        from qerds.services.security_events import (
            SecurityActor,
            SecurityEventPayload,
            SecurityEventType,
        )

        actor = SecurityActor(
            actor_id=str(admin_user.principal_id),
            actor_type=admin_user.principal_type,
            ip_address=admin_user.ip_address,
            user_agent=admin_user.user_agent,
            session_id=str(admin_user.session_id),
        )

        payload = SecurityEventPayload(
            event_type=SecurityEventType.ADMIN_ACTION,
            actor=actor,
            action="create_user",
            resource_type="user",
            resource_id=str(uuid4()),
            outcome="completed",
            details={"username": "newuser"},
        )

        payload_dict = payload.to_dict()
        assert payload_dict["event_type"] == "admin_action"
        assert payload_dict["actor"]["actor_id"] == str(admin_user.principal_id)
        assert payload_dict["resource_type"] == "user"


# ---------------------------------------------------------------------------
# Tests: require_permission decorator
# ---------------------------------------------------------------------------


class TestRequirePermissionDecoratorIntegration:
    """Integration tests for require_permission decorator."""

    def test_decorator_allows_permitted_sync_action(self) -> None:
        """Decorator allows sync function when permission granted."""
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
            return "admin_action_completed"

        result = protected_action()
        assert result == "admin_action_completed"

    @pytest.mark.asyncio
    async def test_decorator_allows_permitted_async_action(self) -> None:
        """Decorator allows async function when permission granted."""
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
            return "async_admin_action_completed"

        result = await async_protected_action()
        assert result == "async_admin_action_completed"

    def test_decorator_denies_unpermitted_action(self) -> None:
        """Decorator denies function when permission not granted."""
        sender = Principal(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
            is_active=True,
        )

        @require_permission_decorator(
            Permission.ADMIN_ACCESS,
            get_principal=lambda: sender,
        )
        def protected_action() -> str:
            return "should_not_reach"

        with pytest.raises(PermissionDeniedError):
            protected_action()

    def test_decorator_denies_inactive_user(self) -> None:
        """Decorator denies function when user is inactive."""
        inactive = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
            is_active=False,
        )

        @require_permission_decorator(
            Permission.ADMIN_ACCESS,
            get_principal=lambda: inactive,
        )
        def protected_action() -> str:
            return "should_not_reach"

        with pytest.raises(InactiveAccountError):
            protected_action()

    def test_decorator_requires_dual_control(self) -> None:
        """Decorator requires dual-control for sensitive operations."""
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
            return "should_not_reach"

        with pytest.raises(DualControlRequiredError):
            sensitive_action()


# ---------------------------------------------------------------------------
# Tests: Context variable management
# ---------------------------------------------------------------------------


class TestContextVariableManagement:
    """Tests for current user context variable management."""

    def test_set_and_get_current_user(self, admin_user: AuthenticatedUser) -> None:
        """set_current_user and get_current_user work correctly."""
        set_current_user(admin_user)
        try:
            result = get_current_user()
            assert result == admin_user
        finally:
            set_current_user(None)

    def test_get_current_user_returns_none_when_not_set(self) -> None:
        """get_current_user returns None when not set."""
        set_current_user(None)
        result = get_current_user()
        assert result is None

    def test_context_isolation_between_calls(
        self, admin_user: AuthenticatedUser, sender_user: AuthenticatedUser
    ) -> None:
        """Context can be changed between calls."""
        set_current_user(admin_user)
        assert get_current_user() == admin_user

        set_current_user(sender_user)
        assert get_current_user() == sender_user

        set_current_user(None)
        assert get_current_user() is None


# ---------------------------------------------------------------------------
# Tests: Error classes
# ---------------------------------------------------------------------------


class TestAuthorizationErrorClasses:
    """Tests for authorization error classes."""

    def test_permission_denied_error_carries_permission(self) -> None:
        """PermissionDeniedError carries the denied permission."""
        error = PermissionDeniedError(
            "Access denied",
            permission=Permission.ADMIN_ACCESS,
        )
        assert error.permission == Permission.ADMIN_ACCESS
        assert "Access denied" in str(error)

    def test_dual_control_required_error_carries_request_id(self) -> None:
        """DualControlRequiredError carries request ID when available."""
        request_id = uuid4()
        error = DualControlRequiredError(
            "Dual control required",
            permission=Permission.KEY_MANAGEMENT,
            request_id=request_id,
        )
        assert error.permission == Permission.KEY_MANAGEMENT
        assert error.request_id == request_id

    def test_inactive_account_error_is_authorization_error(self) -> None:
        """InactiveAccountError is an AuthorizationError."""
        from qerds.services.authz import AuthorizationError

        error = InactiveAccountError("Account inactive")
        assert isinstance(error, AuthorizationError)

    def test_separation_of_duties_error_is_authorization_error(self) -> None:
        """SeparationOfDutiesError is an AuthorizationError."""
        from qerds.services.authz import AuthorizationError

        error = SeparationOfDutiesError(
            "Cannot combine roles",
            permission=Permission.ADMIN_ACCESS,
        )
        assert isinstance(error, AuthorizationError)


# ---------------------------------------------------------------------------
# Tests: All dual-control permissions are documented
# ---------------------------------------------------------------------------


class TestDualControlPermissionsCompleteness:
    """Tests to ensure dual-control permissions are properly defined."""

    def test_all_dual_control_permissions_documented(self) -> None:
        """All dual-control permissions are in the DUAL_CONTROL_PERMISSIONS set."""
        # These are the permissions that MUST require dual-control
        expected_dual_control = {
            Permission.KEY_MANAGEMENT,
            Permission.CONFIG_CHANGE,
            Permission.SECURITY_SETTINGS,
            Permission.EXPORT_AUDIT_LOGS,
        }

        assert expected_dual_control == DUAL_CONTROL_PERMISSIONS

    def test_dual_control_permissions_are_not_in_admin_role(self) -> None:
        """Dual-control permissions are not automatically granted to admin."""
        admin_perms = ROLE_PERMISSIONS[RoleClass.ADMIN]
        for perm in DUAL_CONTROL_PERMISSIONS:
            assert perm not in admin_perms, f"{perm} should not be in admin permissions"

    def test_security_officer_has_dual_control_permissions(self) -> None:
        """Security officer has the base permissions for dual-control ops."""
        security_perms = ROLE_PERMISSIONS[RoleClass.SECURITY_OFFICER]

        # Security officer should have key management and config change
        assert Permission.KEY_MANAGEMENT in security_perms
        assert Permission.CONFIG_CHANGE in security_perms


# ---------------------------------------------------------------------------
# Tests: ABACContext functionality
# ---------------------------------------------------------------------------


class TestABACContextFunctionality:
    """Tests for ABACContext dataclass functionality."""

    def test_abac_context_default_values(self) -> None:
        """ABACContext has sensible defaults."""
        ctx = ABACContext()
        assert ctx.environment == Environment.PRODUCTION
        assert ctx.access_purpose == AccessPurpose.NORMAL_OPERATION
        assert ctx.organization_ids == frozenset()
        assert ctx.assigned_delivery_ids == frozenset()

    def test_abac_context_is_frozen(self) -> None:
        """ABACContext is immutable."""
        ctx = ABACContext()
        with pytest.raises(AttributeError):
            ctx.environment = Environment.STAGING  # type: ignore

    def test_is_assigned_to_delivery_checks_set(self) -> None:
        """is_assigned_to_delivery correctly checks assignment set."""
        delivery_id = uuid4()
        other_id = uuid4()

        ctx = ABACContext(assigned_delivery_ids=frozenset([delivery_id]))

        assert ctx.is_assigned_to_delivery(delivery_id)
        assert not ctx.is_assigned_to_delivery(other_id)

    def test_is_member_of_organization_checks_set(self) -> None:
        """is_member_of_organization correctly checks membership set."""
        org_id = uuid4()
        other_org = uuid4()

        ctx = ABACContext(organization_ids=frozenset([org_id]))

        assert ctx.is_member_of_organization(org_id)
        assert not ctx.is_member_of_organization(other_org)


# ---------------------------------------------------------------------------
# Tests: Principal role class extraction
# ---------------------------------------------------------------------------


class TestPrincipalRoleClassExtraction:
    """Tests for Principal.get_role_classes method."""

    def test_extracts_standard_role_classes(self) -> None:
        """Standard role names are converted to RoleClass enums."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "auditor"]),
        )

        role_classes = principal.get_role_classes()
        assert RoleClass.ADMIN in role_classes
        assert RoleClass.AUDITOR in role_classes

    def test_ignores_custom_roles(self) -> None:
        """Custom/unknown role names are silently ignored."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin", "custom_role", "another_custom"]),
        )

        role_classes = principal.get_role_classes()
        assert RoleClass.ADMIN in role_classes
        assert len(role_classes) == 1  # Only admin is recognized

    def test_empty_roles_returns_empty_set(self) -> None:
        """Empty roles returns empty set."""
        principal = Principal(
            principal_id=uuid4(),
            principal_type="party",
        )

        role_classes = principal.get_role_classes()
        assert role_classes == frozenset()


# ---------------------------------------------------------------------------
# Tests: All role classes have permission mappings
# ---------------------------------------------------------------------------


class TestRolePermissionMappingsCompleteness:
    """Tests to ensure all role classes are properly mapped."""

    def test_all_role_classes_have_mappings(self) -> None:
        """Every RoleClass enum has a permission mapping."""
        for role_class in RoleClass:
            assert role_class in ROLE_PERMISSIONS, f"{role_class} missing from ROLE_PERMISSIONS"

    def test_all_mappings_have_at_least_one_permission(self) -> None:
        """Each role class has at least one permission."""
        for role_class, permissions in ROLE_PERMISSIONS.items():
            assert len(permissions) > 0, f"{role_class} has no permissions"

    def test_permission_values_are_valid_enums(self) -> None:
        """All mapped permissions are valid Permission enums."""
        for role_class, permissions in ROLE_PERMISSIONS.items():
            for perm in permissions:
                assert isinstance(perm, Permission), f"Invalid permission in {role_class}: {perm}"
