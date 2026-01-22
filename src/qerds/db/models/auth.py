"""Authentication and authorization models: users, clients, roles, bindings.

Covers: REQ-D02 (access control), REQ-H06 (access review)
"""

from __future__ import annotations

import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qerds.db.models.base import (
    Base,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)


class AdminUser(Base):
    """Administrative user account (REQ-D02).

    Represents a human operator with access to administrative functions.
    Supports both local auth and external identity providers.
    """

    __tablename__ = "admin_users"

    admin_user_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Login credentials
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    # Password hash (argon2id preferred) - null if using external auth only
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Display name for audit logs
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # External identity provider (e.g., OIDC)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    external_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # MFA status
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Session management
    last_login_at: Mapped[OptionalTimestampTZ]
    password_changed_at: Mapped[OptionalTimestampTZ]

    # Account lockout
    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[OptionalTimestampTZ]

    # Additional metadata
    user_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    role_bindings: Mapped[list[RoleBinding]] = relationship(
        "RoleBinding",
        foreign_keys="RoleBinding.admin_user_id",
        back_populates="admin_user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (Index("ix_admin_users_external_id", "external_provider", "external_id"),)


class ApiClient(Base):
    """API client credentials (REQ-D02).

    Represents a machine-to-machine client with API access.
    Used for external integrations and service accounts.
    """

    __tablename__ = "api_clients"

    api_client_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Client identification
    client_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Client secret hash (for client_credentials flow)
    # The actual secret is only shown once at creation
    client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Allowed scopes for this client
    allowed_scopes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(100)),
        nullable=True,
    )

    # Rate limiting
    rate_limit_per_minute: Mapped[int | None] = mapped_column(nullable=True)

    # IP allowlist (CIDR notation)
    allowed_ips: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(50)),
        nullable=True,
    )

    # Expiry for temporary clients
    expires_at: Mapped[OptionalTimestampTZ]

    # Who created/owns this client
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.admin_user_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Usage tracking
    last_used_at: Mapped[OptionalTimestampTZ]

    # Additional metadata
    client_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    role_bindings: Mapped[list[RoleBinding]] = relationship(
        "RoleBinding",
        foreign_keys="RoleBinding.api_client_id",
        back_populates="api_client",
        cascade="all, delete-orphan",
    )

    __table_args__ = (Index("ix_api_clients_client_id", "client_id"),)


class Role(Base):
    """Role definition for RBAC (REQ-D02).

    Defines a named role with a set of permissions.
    Roles are assigned to users/clients via RoleBinding.
    """

    __tablename__ = "roles"

    role_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Role identification
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Permissions granted by this role (list of permission strings)
    # e.g., ["deliveries:read", "deliveries:write", "admin:users:read"]
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)),
        nullable=False,
        default=[],
    )

    # Whether this is a system-defined role (cannot be deleted)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Role hierarchy - parent role whose permissions are inherited
    parent_role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.role_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    bindings: Mapped[list[RoleBinding]] = relationship(
        "RoleBinding",
        back_populates="role",
        cascade="all, delete-orphan",
    )

    __table_args__ = (Index("ix_roles_name", "name"),)


class RoleBinding(Base):
    """Role assignment to user or client (REQ-D02, REQ-H06).

    Associates a role with either an admin user or an API client.
    Supports scope limiting and time-bounded access.
    """

    __tablename__ = "role_bindings"

    binding_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.role_id", ondelete="CASCADE"),
        nullable=False,
    )

    # One of these must be set (enforced at application level)
    admin_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.admin_user_id", ondelete="CASCADE"),
        nullable=True,
    )
    api_client_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("api_clients.api_client_id", ondelete="CASCADE"),
        nullable=True,
    )

    # Scope limiting (e.g., only certain jurisdictions or delivery IDs)
    scope_filter: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Time-bounded access
    valid_from: Mapped[OptionalTimestampTZ]
    valid_until: Mapped[OptionalTimestampTZ]

    # Who granted this binding (for audit)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Reason for the binding (for access reviews)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    role: Mapped[Role] = relationship("Role", back_populates="bindings")
    admin_user: Mapped[AdminUser | None] = relationship(
        "AdminUser",
        foreign_keys=[admin_user_id],
        back_populates="role_bindings",
    )
    api_client: Mapped[ApiClient | None] = relationship(
        "ApiClient",
        foreign_keys=[api_client_id],
        back_populates="role_bindings",
    )

    __table_args__ = (
        Index("ix_role_bindings_role_id", "role_id"),
        Index("ix_role_bindings_admin_user_id", "admin_user_id"),
        Index("ix_role_bindings_api_client_id", "api_client_id"),
        # Prevent duplicate bindings for the same role/user or role/client
        UniqueConstraint("role_id", "admin_user_id", name="uq_role_bindings_role_admin_user"),
        UniqueConstraint("role_id", "api_client_id", name="uq_role_bindings_role_api_client"),
    )
