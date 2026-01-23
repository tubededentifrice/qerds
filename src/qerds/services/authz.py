"""Authorization service for RBAC/ABAC access control.

Covers: REQ-D02 (access control), REQ-H06 (access review)

This module provides:
- Permission definitions for all platform operations
- Role classes with permission mappings
- ABAC attribute-based access control
- Dual-control enforcement for sensitive operations

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Permission definitions
# ---------------------------------------------------------------------------


class Permission(str, Enum):
    """Permissions for platform operations.

    These are granular capabilities that can be granted via roles.
    Permission names follow the pattern: RESOURCE_ACTION.
    """

    # Delivery operations
    VIEW_DELIVERIES = "view_deliveries"
    CREATE_DELIVERY = "create_delivery"
    UPDATE_DELIVERY = "update_delivery"
    DELETE_DELIVERY = "delete_delivery"
    ACCEPT_DELIVERY = "accept_delivery"
    REFUSE_DELIVERY = "refuse_delivery"

    # Evidence operations
    VIEW_EVIDENCE = "view_evidence"
    EXPORT_EVIDENCE = "export_evidence"

    # Content operations
    VIEW_CONTENT = "view_content"
    UPLOAD_CONTENT = "upload_content"

    # Administrative operations
    ADMIN_ACCESS = "admin_access"
    VIEW_USERS = "view_users"
    MANAGE_USERS = "manage_users"
    VIEW_CLIENTS = "view_clients"
    MANAGE_CLIENTS = "manage_clients"
    VIEW_ROLES = "view_roles"
    MANAGE_ROLES = "manage_roles"

    # Audit operations
    AUDIT_ACCESS = "audit_access"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_AUDIT_LOGS = "export_audit_logs"

    # Security operations (require dual-control)
    KEY_MANAGEMENT = "key_management"
    CONFIG_CHANGE = "config_change"
    SECURITY_SETTINGS = "security_settings"

    # Identity verification
    VERIFY_IDENTITY = "verify_identity"
    MANAGE_IDENTITY_PROOFS = "manage_identity_proofs"

    # Support operations
    VIEW_SUPPORT_CASES = "view_support_cases"
    MANAGE_SUPPORT_CASES = "manage_support_cases"


# ---------------------------------------------------------------------------
# Role classes
# ---------------------------------------------------------------------------


class RoleClass(str, Enum):
    """Role classes defined per specification.

    These map to the role classes in specs/implementation/20-identities-and-roles.md.
    Each role class has a predefined set of permissions.
    """

    ADMIN = "admin"
    SECURITY_OFFICER = "security_officer"
    AUDITOR = "auditor"
    SUPPORT = "support"
    REGISTRATION_OFFICER = "registration_officer"
    SENDER_USER = "sender_user"
    RECIPIENT_USER = "recipient_user"
    API_CLIENT = "api_client"


# ---------------------------------------------------------------------------
# Role-to-permission mappings
# ---------------------------------------------------------------------------

# Permissions granted to each role class.
# Roles accumulate permissions from their definition; no inheritance is applied here.
# More specific permissions can be added via Role.permissions in the database.

ROLE_PERMISSIONS: dict[RoleClass, frozenset[Permission]] = {
    RoleClass.ADMIN: frozenset(
        [
            Permission.ADMIN_ACCESS,
            Permission.VIEW_USERS,
            Permission.MANAGE_USERS,
            Permission.VIEW_CLIENTS,
            Permission.MANAGE_CLIENTS,
            Permission.VIEW_ROLES,
            Permission.MANAGE_ROLES,
            Permission.VIEW_DELIVERIES,
            Permission.VIEW_EVIDENCE,
            Permission.VIEW_AUDIT_LOGS,
            # Note: KEY_MANAGEMENT and CONFIG_CHANGE require dual-control
            # and are not automatically granted even to admins
        ]
    ),
    RoleClass.SECURITY_OFFICER: frozenset(
        [
            Permission.KEY_MANAGEMENT,
            Permission.CONFIG_CHANGE,
            Permission.SECURITY_SETTINGS,
            Permission.VIEW_AUDIT_LOGS,
            Permission.EXPORT_AUDIT_LOGS,
            Permission.VIEW_USERS,
            Permission.VIEW_CLIENTS,
        ]
    ),
    RoleClass.AUDITOR: frozenset(
        [
            Permission.AUDIT_ACCESS,
            Permission.VIEW_AUDIT_LOGS,
            Permission.EXPORT_AUDIT_LOGS,
            Permission.VIEW_DELIVERIES,
            Permission.VIEW_EVIDENCE,
            Permission.EXPORT_EVIDENCE,
            Permission.VIEW_USERS,
            Permission.VIEW_CLIENTS,
        ]
    ),
    RoleClass.SUPPORT: frozenset(
        [
            Permission.VIEW_SUPPORT_CASES,
            Permission.MANAGE_SUPPORT_CASES,
            Permission.VIEW_DELIVERIES,
            Permission.VIEW_USERS,
        ]
    ),
    RoleClass.REGISTRATION_OFFICER: frozenset(
        [
            Permission.VERIFY_IDENTITY,
            Permission.MANAGE_IDENTITY_PROOFS,
            Permission.VIEW_USERS,
        ]
    ),
    RoleClass.SENDER_USER: frozenset(
        [
            Permission.CREATE_DELIVERY,
            Permission.VIEW_DELIVERIES,  # Only their own deliveries (via ABAC)
            Permission.UPDATE_DELIVERY,  # Only their own deliveries (via ABAC)
            Permission.DELETE_DELIVERY,  # Only drafts they own (via ABAC)
            Permission.VIEW_EVIDENCE,  # Only their own deliveries (via ABAC)
            Permission.VIEW_CONTENT,  # Only their own deliveries (via ABAC)
            Permission.UPLOAD_CONTENT,
        ]
    ),
    RoleClass.RECIPIENT_USER: frozenset(
        [
            Permission.VIEW_DELIVERIES,  # Only deliveries addressed to them (via ABAC)
            Permission.ACCEPT_DELIVERY,
            Permission.REFUSE_DELIVERY,
            Permission.VIEW_EVIDENCE,  # Only their deliveries (via ABAC)
            Permission.VIEW_CONTENT,  # Only after acceptance (via ABAC)
        ]
    ),
    RoleClass.API_CLIENT: frozenset(
        [
            # API clients get minimal permissions by default.
            # Actual permissions are controlled via allowed_scopes in ApiClient model.
            Permission.CREATE_DELIVERY,
            Permission.VIEW_DELIVERIES,
        ]
    ),
}

# Permissions that require dual-control approval
DUAL_CONTROL_PERMISSIONS: frozenset[Permission] = frozenset(
    [
        Permission.KEY_MANAGEMENT,
        Permission.CONFIG_CHANGE,
        Permission.SECURITY_SETTINGS,
        Permission.EXPORT_AUDIT_LOGS,
    ]
)


# ---------------------------------------------------------------------------
# ABAC Attributes
# ---------------------------------------------------------------------------


class Environment(str, Enum):
    """Environment context for ABAC decisions."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


class AccessPurpose(str, Enum):
    """Purpose of access for ABAC decisions.

    Required for logging and compliance per REQ-D02.
    """

    NORMAL_OPERATION = "normal_operation"
    INVESTIGATION = "investigation"
    SUPPORT_REQUEST = "support_request"
    AUDIT = "audit"
    MAINTENANCE = "maintenance"
    EMERGENCY = "emergency"


@dataclass(frozen=True)
class ABACContext:
    """Attribute-based access control context.

    Contains attributes used for fine-grained authorization decisions
    beyond simple RBAC permission checks.
    """

    # Organization context
    organization_id: UUID | None = None
    organization_ids: frozenset[UUID] = field(default_factory=frozenset)

    # Resource assignment
    delivery_id: UUID | None = None
    case_id: UUID | None = None
    assigned_delivery_ids: frozenset[UUID] = field(default_factory=frozenset)
    assigned_case_ids: frozenset[UUID] = field(default_factory=frozenset)

    # Environment and purpose
    environment: Environment = Environment.PRODUCTION
    access_purpose: AccessPurpose = AccessPurpose.NORMAL_OPERATION

    # Time-based constraints
    access_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Request metadata
    ip_address: str | None = None
    user_agent: str | None = None

    def is_assigned_to_delivery(self, delivery_id: UUID) -> bool:
        """Check if the context includes assignment to a specific delivery."""
        return delivery_id in self.assigned_delivery_ids

    def is_member_of_organization(self, org_id: UUID) -> bool:
        """Check if the context includes membership in a specific organization."""
        return org_id in self.organization_ids


# ---------------------------------------------------------------------------
# Principal representation
# ---------------------------------------------------------------------------


@dataclass
class Principal:
    """Represents an authenticated principal (user or client).

    This is the subject of authorization decisions. It carries:
    - Identity information
    - Role bindings (RBAC)
    - ABAC attributes
    """

    # Identity
    principal_id: UUID
    principal_type: str  # "admin_user", "api_client", "sender_user", "recipient_user"

    # RBAC - role bindings
    roles: frozenset[str] = field(default_factory=frozenset)

    # Additional permissions from role definitions in database
    # These are accumulated from Role.permissions for all bound roles
    explicit_permissions: frozenset[str] = field(default_factory=frozenset)

    # ABAC context
    abac_context: ABACContext = field(default_factory=ABACContext)

    # Superuser flag (bypasses most permission checks)
    is_superuser: bool = False

    # Active status
    is_active: bool = True

    def get_role_classes(self) -> frozenset[RoleClass]:
        """Convert role names to RoleClass enums."""
        result = set()
        for role_name in self.roles:
            # Custom roles (not standard role classes) are silently ignored
            with contextlib.suppress(ValueError):
                result.add(RoleClass(role_name))
        return frozenset(result)


# ---------------------------------------------------------------------------
# Dual-control support
# ---------------------------------------------------------------------------


@dataclass
class DualControlRequest:
    """Request for dual-control approval of a sensitive operation.

    Sensitive operations (key management, config changes) require
    approval from a second authorized principal before execution.
    """

    request_id: UUID
    operation: str
    permission: Permission
    requested_by: UUID
    requested_at: datetime
    reason: str
    parameters: dict[str, Any] = field(default_factory=dict)

    # Approval state
    approved_by: UUID | None = None
    approved_at: datetime | None = None
    rejected_by: UUID | None = None
    rejected_at: datetime | None = None
    rejection_reason: str | None = None

    # Expiry for pending requests
    expires_at: datetime | None = None

    @property
    def is_pending(self) -> bool:
        """Check if the request is still pending approval."""
        return self.approved_by is None and self.rejected_by is None

    @property
    def is_approved(self) -> bool:
        """Check if the request has been approved."""
        return self.approved_by is not None

    @property
    def is_rejected(self) -> bool:
        """Check if the request has been rejected."""
        return self.rejected_by is not None

    @property
    def is_expired(self) -> bool:
        """Check if the request has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at


# ---------------------------------------------------------------------------
# Authorization errors
# ---------------------------------------------------------------------------


class AuthorizationError(Exception):
    """Base exception for authorization failures."""

    def __init__(self, message: str, permission: Permission | None = None) -> None:
        self.permission = permission
        super().__init__(message)


class PermissionDeniedError(AuthorizationError):
    """Raised when a principal lacks required permission."""

    pass


class DualControlRequiredError(AuthorizationError):
    """Raised when an operation requires dual-control approval."""

    def __init__(
        self,
        message: str,
        permission: Permission,
        request_id: UUID | None = None,
    ) -> None:
        self.request_id = request_id
        super().__init__(message, permission)


class InactiveAccountError(AuthorizationError):
    """Raised when the principal's account is not active."""

    pass


class SeparationOfDutiesError(AuthorizationError):
    """Raised when an operation violates separation of duties rules."""

    pass


# ---------------------------------------------------------------------------
# Authorization Service
# ---------------------------------------------------------------------------


class AuthorizationService:
    """Service for checking permissions and enforcing access control.

    This service implements:
    - RBAC: Role-based permission checks
    - ABAC: Attribute-based fine-grained access control
    - Dual-control: Approval workflow for sensitive operations
    - Separation of duties: Preventing conflicting role combinations
    """

    def __init__(self) -> None:
        """Initialize the authorization service."""
        # In-memory pending dual-control requests for testing.
        # Production should use a persistent store.
        self._pending_dual_control: dict[UUID, DualControlRequest] = {}

    def get_role_permissions(self, role_class: RoleClass) -> frozenset[Permission]:
        """Get the permissions granted by a role class.

        Args:
            role_class: The role class to query.

        Returns:
            Set of permissions granted by this role class.
        """
        return ROLE_PERMISSIONS.get(role_class, frozenset())

    def get_all_permissions(self, principal: Principal) -> frozenset[Permission]:
        """Get all permissions available to a principal.

        Combines:
        - Permissions from role class definitions
        - Explicit permissions from Role.permissions in database

        Args:
            principal: The authenticated principal.

        Returns:
            Combined set of all available permissions.
        """
        if not principal.is_active:
            return frozenset()

        permissions: set[Permission] = set()

        # Accumulate permissions from role classes
        for role_class in principal.get_role_classes():
            permissions.update(ROLE_PERMISSIONS.get(role_class, frozenset()))

        # Add explicit permissions from database role definitions
        for perm_str in principal.explicit_permissions:
            try:
                permissions.add(Permission(perm_str))
            except ValueError:
                # Unknown permission string, skip
                logger.warning("Unknown permission string: %s", perm_str)

        return frozenset(permissions)

    def has_permission(
        self,
        principal: Principal,
        permission: Permission,
        resource: Any | None = None,
    ) -> bool:
        """Check if a principal has a specific permission.

        This performs RBAC check followed by optional ABAC resource check.

        Args:
            principal: The authenticated principal.
            permission: The permission to check.
            resource: Optional resource for ABAC checks (e.g., a Delivery object).

        Returns:
            True if access is granted, False otherwise.
        """
        # Inactive accounts have no permissions
        if not principal.is_active:
            return False

        # Superusers bypass permission checks (except dual-control requirements)
        if principal.is_superuser and permission not in DUAL_CONTROL_PERMISSIONS:
            return True

        # Check RBAC permissions
        all_permissions = self.get_all_permissions(principal)
        if permission not in all_permissions:
            return False

        # If a resource is provided, check ABAC constraints
        if resource is not None:
            return self._check_abac_constraints(principal, permission, resource)

        return True

    def require_permission(
        self,
        principal: Principal,
        permission: Permission,
        resource: Any | None = None,
    ) -> None:
        """Require a permission or raise an error.

        Similar to has_permission but raises exceptions on failure.

        Args:
            principal: The authenticated principal.
            permission: The required permission.
            resource: Optional resource for ABAC checks.

        Raises:
            InactiveAccountError: If the account is not active.
            PermissionDeniedError: If the permission is not granted.
            DualControlRequiredError: If dual-control approval is needed.
        """
        if not principal.is_active:
            raise InactiveAccountError(
                "Account is not active",
                permission=permission,
            )

        if not self.has_permission(principal, permission, resource):
            raise PermissionDeniedError(
                f"Permission denied: {permission.value}",
                permission=permission,
            )

    def requires_dual_control(self, permission: Permission) -> bool:
        """Check if a permission requires dual-control approval.

        Args:
            permission: The permission to check.

        Returns:
            True if dual-control is required.
        """
        return permission in DUAL_CONTROL_PERMISSIONS

    def create_dual_control_request(
        self,
        principal: Principal,
        permission: Permission,
        operation: str,
        reason: str,
        parameters: dict[str, Any] | None = None,
        expires_in_hours: int = 24,
    ) -> DualControlRequest:
        """Create a request for dual-control approval.

        Args:
            principal: The principal requesting the operation.
            permission: The permission required for the operation.
            operation: Description of the operation.
            reason: Justification for the operation.
            parameters: Operation-specific parameters.
            expires_in_hours: Hours until the request expires.

        Returns:
            The created dual-control request.

        Raises:
            PermissionDeniedError: If principal lacks the base permission.
        """
        # Principal must have the base permission
        if not self.has_permission(principal, permission):
            raise PermissionDeniedError(
                f"Cannot request dual-control for permission not held: {permission.value}",
                permission=permission,
            )

        from datetime import timedelta

        request_id = UUID(int=hash(f"{principal.principal_id}:{datetime.now(UTC)}") % (2**128))
        now = datetime.now(UTC)

        request = DualControlRequest(
            request_id=request_id,
            operation=operation,
            permission=permission,
            requested_by=principal.principal_id,
            requested_at=now,
            reason=reason,
            parameters=parameters or {},
            expires_at=now + timedelta(hours=expires_in_hours),
        )

        self._pending_dual_control[request_id] = request

        logger.info(
            "Dual-control request created: %s by %s for %s",
            request_id,
            principal.principal_id,
            operation,
        )

        return request

    def approve_dual_control_request(
        self,
        request_id: UUID,
        approver: Principal,
    ) -> DualControlRequest:
        """Approve a dual-control request.

        Args:
            request_id: ID of the request to approve.
            approver: The principal approving the request.

        Returns:
            The updated request.

        Raises:
            ValueError: If request not found or already processed.
            PermissionDeniedError: If approver lacks permission.
            SeparationOfDutiesError: If approver is the same as requester.
        """
        request = self._pending_dual_control.get(request_id)
        if request is None:
            raise ValueError(f"Dual-control request not found: {request_id}")

        if not request.is_pending:
            raise ValueError("Request has already been processed")

        if request.is_expired:
            raise ValueError("Request has expired")

        # Approver must have the permission
        if not self.has_permission(approver, request.permission):
            raise PermissionDeniedError(
                f"Approver lacks permission: {request.permission.value}",
                permission=request.permission,
            )

        # Separation of duties: approver cannot be the requester
        if approver.principal_id == request.requested_by:
            raise SeparationOfDutiesError(
                "Cannot approve own dual-control request",
                permission=request.permission,
            )

        # Approve the request
        now = datetime.now(UTC)
        approved_request = DualControlRequest(
            request_id=request.request_id,
            operation=request.operation,
            permission=request.permission,
            requested_by=request.requested_by,
            requested_at=request.requested_at,
            reason=request.reason,
            parameters=request.parameters,
            expires_at=request.expires_at,
            approved_by=approver.principal_id,
            approved_at=now,
        )

        self._pending_dual_control[request_id] = approved_request

        logger.info(
            "Dual-control request approved: %s by %s",
            request_id,
            approver.principal_id,
        )

        return approved_request

    def reject_dual_control_request(
        self,
        request_id: UUID,
        rejector: Principal,
        reason: str,
    ) -> DualControlRequest:
        """Reject a dual-control request.

        Args:
            request_id: ID of the request to reject.
            rejector: The principal rejecting the request.
            reason: Reason for rejection.

        Returns:
            The updated request.

        Raises:
            ValueError: If request not found or already processed.
            PermissionDeniedError: If rejector lacks permission.
        """
        request = self._pending_dual_control.get(request_id)
        if request is None:
            raise ValueError(f"Dual-control request not found: {request_id}")

        if not request.is_pending:
            raise ValueError("Request has already been processed")

        # Rejector must have the permission
        if not self.has_permission(rejector, request.permission):
            raise PermissionDeniedError(
                f"Rejector lacks permission: {request.permission.value}",
                permission=request.permission,
            )

        # Reject the request
        now = datetime.now(UTC)
        rejected_request = DualControlRequest(
            request_id=request.request_id,
            operation=request.operation,
            permission=request.permission,
            requested_by=request.requested_by,
            requested_at=request.requested_at,
            reason=request.reason,
            parameters=request.parameters,
            expires_at=request.expires_at,
            rejected_by=rejector.principal_id,
            rejected_at=now,
            rejection_reason=reason,
        )

        self._pending_dual_control[request_id] = rejected_request

        logger.info(
            "Dual-control request rejected: %s by %s - %s",
            request_id,
            rejector.principal_id,
            reason,
        )

        return rejected_request

    def check_dual_control_approved(
        self,
        request_id: UUID,
    ) -> bool:
        """Check if a dual-control request has been approved.

        Args:
            request_id: ID of the request to check.

        Returns:
            True if approved, False otherwise.
        """
        request = self._pending_dual_control.get(request_id)
        if request is None:
            return False
        return request.is_approved

    def _check_abac_constraints(
        self,
        principal: Principal,
        permission: Permission,
        resource: Any,
    ) -> bool:
        """Check ABAC constraints for resource access.

        This method performs attribute-based checks to ensure the principal
        can access the specific resource, not just the resource type.

        Args:
            principal: The authenticated principal.
            permission: The permission being checked.
            resource: The resource to check access for.

        Returns:
            True if ABAC constraints are satisfied.
        """
        ctx = principal.abac_context

        # Check resource ownership/assignment based on resource type
        # Resources should have standard attributes we can check

        # Check delivery ownership/assignment
        if hasattr(resource, "delivery_id"):
            delivery_id = resource.delivery_id
            if isinstance(delivery_id, str):
                delivery_id = UUID(delivery_id)

            # Sender can access their own deliveries
            if hasattr(resource, "sender_party_id") and str(resource.sender_party_id) == str(
                principal.principal_id
            ):
                return True

            # Recipient can access deliveries addressed to them
            if hasattr(resource, "recipient_party_id") and str(resource.recipient_party_id) == str(
                principal.principal_id
            ):
                return True

            # Check explicit assignment
            if ctx.is_assigned_to_delivery(delivery_id):
                return True

        # Check organization membership
        if hasattr(resource, "organization_id"):
            org_id = resource.organization_id
            if isinstance(org_id, str):
                org_id = UUID(org_id)
            if ctx.is_member_of_organization(org_id):
                return True

        # Administrative roles can access all resources (after RBAC check passed)
        admin_roles = {RoleClass.ADMIN, RoleClass.AUDITOR, RoleClass.SUPPORT}
        if principal.get_role_classes() & admin_roles:
            return True

        # If we can't determine ownership, deny by default (fail closed)
        logger.warning(
            "ABAC check failed: principal=%s, permission=%s, resource=%s",
            principal.principal_id,
            permission.value,
            type(resource).__name__,
        )
        return False

    def check_separation_of_duties(
        self,
        principal: Principal,
        role_to_add: RoleClass,
    ) -> bool:
        """Check if adding a role would violate separation of duties.

        Certain role combinations are prohibited to enforce security controls.

        Args:
            principal: The principal to check.
            role_to_add: The role being added.

        Returns:
            True if the role can be added without violation.
        """
        current_roles = principal.get_role_classes()

        # Define incompatible role pairs
        incompatible_pairs: list[tuple[RoleClass, RoleClass]] = [
            # Admins cannot be auditors (prevent self-audit)
            (RoleClass.ADMIN, RoleClass.AUDITOR),
            # Security officers cannot be admins (dual-control enforcement)
            (RoleClass.SECURITY_OFFICER, RoleClass.ADMIN),
            # Registration officers cannot be regular users
            (RoleClass.REGISTRATION_OFFICER, RoleClass.SENDER_USER),
            (RoleClass.REGISTRATION_OFFICER, RoleClass.RECIPIENT_USER),
        ]

        for role_a, role_b in incompatible_pairs:
            if role_to_add == role_a and role_b in current_roles:
                return False
            if role_to_add == role_b and role_a in current_roles:
                return False

        return True


# ---------------------------------------------------------------------------
# Decorator for endpoint protection
# ---------------------------------------------------------------------------


def require_permission_decorator(
    permission: Permission,
    get_principal: Callable[..., Principal | Awaitable[Principal]],
    get_resource: Callable[..., Any | Awaitable[Any] | None] | None = None,
) -> Callable:
    """Decorator factory for protecting endpoints with permission checks.

    This decorator wraps endpoint functions to check permissions before execution.
    It supports both sync and async endpoints.

    Args:
        permission: The permission required to access the endpoint.
        get_principal: Callable that extracts the Principal from the request.
        get_resource: Optional callable that extracts the resource for ABAC checks.

    Returns:
        Decorator that wraps the endpoint function.

    Example:
        @require_permission_decorator(
            Permission.VIEW_DELIVERIES,
            get_principal=lambda request: request.state.principal,
            get_resource=lambda delivery_id: get_delivery(delivery_id),
        )
        async def get_delivery(request, delivery_id: str):
            ...
    """
    authz = AuthorizationService()

    def decorator(func: Callable) -> Callable:
        import asyncio
        import inspect

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get principal
            principal_result = get_principal(*args, **kwargs)
            if asyncio.iscoroutine(principal_result):
                principal = await principal_result
            else:
                principal = principal_result

            # Get resource if specified
            resource = None
            if get_resource is not None:
                resource_result = get_resource(*args, **kwargs)
                if asyncio.iscoroutine(resource_result):
                    resource = await resource_result
                else:
                    resource = resource_result

            # Check permission
            authz.require_permission(principal, permission, resource)

            # Check dual-control if required
            if authz.requires_dual_control(permission):
                raise DualControlRequiredError(
                    f"Operation requires dual-control approval: {permission.value}",
                    permission=permission,
                )

            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get principal
            principal = get_principal(*args, **kwargs)

            # Get resource if specified
            resource = None
            if get_resource is not None:
                resource = get_resource(*args, **kwargs)

            # Check permission
            authz.require_permission(principal, permission, resource)

            # Check dual-control if required
            if authz.requires_dual_control(permission):
                raise DualControlRequiredError(
                    f"Operation requires dual-control approval: {permission.value}",
                    permission=permission,
                )

            return func(*args, **kwargs)

        # Return appropriate wrapper based on whether func is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
