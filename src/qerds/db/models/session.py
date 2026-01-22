"""Session model for authenticated user sessions.

Covers: REQ-D02 (access control)

This module provides the Session model for managing authenticated user sessions.
Sessions are database-backed for:
- Multi-device support (user can have multiple active sessions)
- Session revocation (admin can revoke sessions)
- Session expiration (automatic cleanup of stale sessions)
- Audit trail (session activity is logged to security stream)
"""

from __future__ import annotations

import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qerds.db.models.base import (
    Base,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)


class Session(Base):
    """User session for authenticated access.

    Sessions track authenticated users across requests, supporting:
    - Multiple concurrent sessions per user (multi-device)
    - Session-level revocation
    - Device/user-agent tracking for security
    - Activity timestamps for idle timeout
    - Refresh token rotation

    Session tokens are cryptographically random and stored as hashes
    to prevent exposure even if database is compromised.
    """

    __tablename__ = "sessions"

    session_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]
    updated_at: Mapped[TimestampTZ]

    # Token hash (SHA-256 of the actual token)
    # The actual token is only given to the user once at creation
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    # Principal linkage - one of these must be set
    # (enforced at application level via check constraint would require custom migration)
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
    # Party ID for sender/recipient users (references parties table)
    party_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parties.party_id", ondelete="CASCADE"),
        nullable=True,
    )

    # Session type for quick filtering
    session_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="user",
    )

    # Session validity
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[TimestampTZ]

    # Activity tracking
    last_activity_at: Mapped[TimestampTZ]
    activity_count: Mapped[int] = mapped_column(default=0, nullable=False)

    # Device/client information for security review
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Geographic info (from IP geolocation, if available)
    geo_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    geo_city: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Refresh token support for token rotation
    refresh_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    refresh_expires_at: Mapped[OptionalTimestampTZ]

    # Revocation tracking
    revoked_at: Mapped[OptionalTimestampTZ]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Additional metadata (e.g., auth method, MFA status)
    session_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships (lazy loaded)
    admin_user: Mapped[AdminUser | None] = relationship(  # noqa: F821
        "AdminUser",
        foreign_keys=[admin_user_id],
        lazy="select",
    )
    api_client: Mapped[ApiClient | None] = relationship(  # noqa: F821
        "ApiClient",
        foreign_keys=[api_client_id],
        lazy="select",
    )
    party: Mapped[Party | None] = relationship(  # noqa: F821
        "Party",
        foreign_keys=[party_id],
        lazy="select",
    )

    __table_args__ = (
        # Index for token lookup (most common operation)
        Index("ix_sessions_token_hash", "token_hash"),
        # Index for finding sessions by user
        Index("ix_sessions_admin_user_id", "admin_user_id"),
        Index("ix_sessions_api_client_id", "api_client_id"),
        Index("ix_sessions_party_id", "party_id"),
        # Index for cleanup of expired sessions
        Index("ix_sessions_expires_at", "expires_at"),
        # Index for finding active sessions
        Index("ix_sessions_is_active", "is_active"),
        # Composite index for active user sessions
        Index(
            "ix_sessions_admin_user_active",
            "admin_user_id",
            "is_active",
            postgresql_where=(is_active == True),  # noqa: E712 - SQLAlchemy requires ==
        ),
    )

    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        from datetime import UTC, datetime

        return datetime.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if the session has been revoked."""
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if the session is still valid for use."""
        return self.is_active and not self.is_expired and not self.is_revoked

    def get_principal_id(self) -> uuid.UUID | None:
        """Get the principal ID regardless of principal type."""
        return self.admin_user_id or self.api_client_id or self.party_id

    def get_principal_type(self) -> str:
        """Get the type of principal this session belongs to."""
        if self.admin_user_id:
            return "admin_user"
        if self.api_client_id:
            return "api_client"
        if self.party_id:
            return "party"
        return "unknown"
