"""Session management service.

Covers: REQ-D02 (access control)

This module provides session management for authenticated users:
- Secure session token generation
- Database-backed session storage
- Session validation and expiration
- Multi-device support
- Session revocation (single or all user sessions)
- Security event logging for all session operations

Reference: specs/implementation/20-identities-and-roles.md
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, select, update

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.session import Session

logger = logging.getLogger(__name__)

# Session configuration defaults
DEFAULT_SESSION_DURATION_HOURS = 24
DEFAULT_REFRESH_DURATION_HOURS = 168  # 7 days
DEFAULT_IDLE_TIMEOUT_MINUTES = 30
SESSION_TOKEN_BYTES = 32  # 256 bits of entropy
REFRESH_TOKEN_BYTES = 32  # 256 bits of entropy


@dataclass(frozen=True, slots=True)
class SessionToken:
    """Represents a session token pair.

    Attributes:
        session_id: UUID of the session record
        access_token: The access token for API requests
        refresh_token: The refresh token for obtaining new access tokens
        expires_at: When the access token expires
        refresh_expires_at: When the refresh token expires
    """

    session_id: UUID
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    refresh_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class SessionInfo:
    """Information about a session for display/management.

    Attributes:
        session_id: UUID of the session
        session_type: Type of session (admin, api_client, party)
        principal_id: ID of the authenticated principal
        principal_type: Type of principal
        created_at: When the session was created
        expires_at: When the session expires
        last_activity_at: Last activity timestamp
        ip_address: IP address that created the session
        user_agent: User agent string
        is_active: Whether the session is currently active
        is_current: Whether this is the current session (for display)
    """

    session_id: UUID
    session_type: str
    principal_id: UUID | None
    principal_type: str
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    ip_address: str | None
    user_agent: str | None
    is_active: bool
    is_current: bool = False


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Information about the device/client creating a session.

    Attributes:
        ip_address: Client IP address
        user_agent: HTTP User-Agent header
        device_id: Optional device identifier (for mobile apps)
        geo_country: Country code from IP geolocation
        geo_city: City from IP geolocation
    """

    ip_address: str | None = None
    user_agent: str | None = None
    device_id: str | None = None
    geo_country: str | None = None
    geo_city: str | None = None


class SessionError(Exception):
    """Base exception for session operations."""

    pass


class SessionNotFoundError(SessionError):
    """Raised when a session is not found."""

    pass


class SessionExpiredError(SessionError):
    """Raised when attempting to use an expired session."""

    pass


class SessionRevokedError(SessionError):
    """Raised when attempting to use a revoked session."""

    pass


class SessionInvalidError(SessionError):
    """Raised when a session token is invalid."""

    pass


class SessionService:
    """Service for managing user sessions.

    This service provides a complete session management implementation:
    - Cryptographically secure token generation
    - Database-backed session storage
    - Session validation with constant-time comparison
    - Automatic session expiration
    - Multi-device support (multiple concurrent sessions per user)
    - Session revocation (single or all user sessions)
    - Activity tracking for idle timeout
    - Security event logging

    Example:
        service = SessionService(session)

        # Create a session for an admin user
        token = await service.create_session(
            admin_user_id=user_id,
            device_info=DeviceInfo(ip_address="192.168.1.1"),
        )

        # Validate a session token
        session = await service.validate_session(token.access_token)
        if session:
            print(f"Valid session for {session.get_principal_type()}")

        # Revoke a session
        await service.revoke_session(session_id, revoked_by=admin_id)
    """

    def __init__(
        self,
        db_session: AsyncSession,
        *,
        session_duration_hours: int = DEFAULT_SESSION_DURATION_HOURS,
        refresh_duration_hours: int = DEFAULT_REFRESH_DURATION_HOURS,
        idle_timeout_minutes: int = DEFAULT_IDLE_TIMEOUT_MINUTES,
    ) -> None:
        """Initialize the session service.

        Args:
            db_session: SQLAlchemy async session for database operations.
            session_duration_hours: How long access tokens are valid.
            refresh_duration_hours: How long refresh tokens are valid.
            idle_timeout_minutes: Idle timeout for session activity.
        """
        self._db = db_session
        self._session_duration = timedelta(hours=session_duration_hours)
        self._refresh_duration = timedelta(hours=refresh_duration_hours)
        self._idle_timeout = timedelta(minutes=idle_timeout_minutes)

    async def create_session(
        self,
        *,
        admin_user_id: UUID | None = None,
        api_client_id: UUID | None = None,
        party_id: UUID | None = None,
        device_info: DeviceInfo | None = None,
        session_metadata: dict | None = None,
        include_refresh_token: bool = True,
    ) -> SessionToken:
        """Create a new session for a principal.

        Exactly one of admin_user_id, api_client_id, or party_id must be provided.

        Args:
            admin_user_id: ID of the admin user (for admin sessions).
            api_client_id: ID of the API client (for machine sessions).
            party_id: ID of the party (for sender/recipient sessions).
            device_info: Optional device information for security tracking.
            session_metadata: Optional metadata to store with the session.
            include_refresh_token: Whether to generate a refresh token.

        Returns:
            SessionToken containing the access and refresh tokens.

        Raises:
            ValueError: If zero or multiple principal IDs are provided.
        """
        from qerds.db.models.session import Session

        # Validate exactly one principal ID is provided
        principal_count = sum(1 for x in [admin_user_id, api_client_id, party_id] if x is not None)
        if principal_count != 1:
            raise ValueError(
                "Exactly one of admin_user_id, api_client_id, or party_id must be provided"
            )

        # Determine session type
        if admin_user_id:
            session_type = "admin"
        elif api_client_id:
            session_type = "api_client"
        else:
            session_type = "party"

        # Generate secure tokens
        access_token = self._generate_token()
        token_hash = self._hash_token(access_token)

        refresh_token = None
        refresh_token_hash = None
        refresh_expires_at = None
        if include_refresh_token:
            refresh_token = self._generate_token()
            refresh_token_hash = self._hash_token(refresh_token)
            refresh_expires_at = datetime.now(UTC) + self._refresh_duration

        # Calculate expiration
        now = datetime.now(UTC)
        expires_at = now + self._session_duration

        # Extract device info
        device = device_info or DeviceInfo()

        # Create session record
        session = Session(
            token_hash=token_hash,
            admin_user_id=admin_user_id,
            api_client_id=api_client_id,
            party_id=party_id,
            session_type=session_type,
            is_active=True,
            expires_at=expires_at,
            last_activity_at=now,
            activity_count=0,
            ip_address=device.ip_address,
            user_agent=device.user_agent,
            device_id=device.device_id,
            geo_country=device.geo_country,
            geo_city=device.geo_city,
            refresh_token_hash=refresh_token_hash,
            refresh_expires_at=refresh_expires_at,
            session_metadata=session_metadata,
        )

        self._db.add(session)
        await self._db.flush()

        logger.info(
            "Session created: session_id=%s, type=%s, principal=%s",
            session.session_id,
            session_type,
            admin_user_id or api_client_id or party_id,
        )

        return SessionToken(
            session_id=session.session_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            refresh_expires_at=refresh_expires_at,
        )

    async def validate_session(
        self,
        token: str,
        *,
        update_activity: bool = True,
    ) -> Session | None:
        """Validate a session token and return the session if valid.

        Performs constant-time comparison to prevent timing attacks.
        Optionally updates the last activity timestamp.

        Args:
            token: The access token to validate.
            update_activity: Whether to update the last_activity_at timestamp.

        Returns:
            The Session object if valid, None otherwise.
        """
        from qerds.db.models.session import Session

        token_hash = self._hash_token(token)

        # Look up session by token hash
        result = await self._db.execute(select(Session).where(Session.token_hash == token_hash))
        session = result.scalar_one_or_none()

        if session is None:
            logger.debug("Session validation failed: token not found")
            return None

        # Check session validity
        if not session.is_active:
            logger.debug("Session validation failed: session inactive")
            return None

        if session.is_expired:
            logger.debug("Session validation failed: session expired")
            return None

        if session.is_revoked:
            logger.debug("Session validation failed: session revoked")
            return None

        # Update activity timestamp if requested
        if update_activity:
            now = datetime.now(UTC)
            await self._db.execute(
                update(Session)
                .where(Session.session_id == session.session_id)
                .values(
                    last_activity_at=now,
                    activity_count=Session.activity_count + 1,
                    updated_at=now,
                )
            )

        return session

    async def refresh_session(
        self,
        refresh_token: str,
        *,
        device_info: DeviceInfo | None = None,
    ) -> SessionToken:
        """Refresh a session using a refresh token.

        This implements refresh token rotation: the old refresh token
        is invalidated and a new one is issued.

        Args:
            refresh_token: The refresh token.
            device_info: Optional updated device information.

        Returns:
            New SessionToken with fresh access and refresh tokens.

        Raises:
            SessionNotFoundError: If the refresh token is not found.
            SessionExpiredError: If the refresh token has expired.
            SessionRevokedError: If the session has been revoked.
        """
        from qerds.db.models.session import Session

        token_hash = self._hash_token(refresh_token)

        # Look up session by refresh token hash
        result = await self._db.execute(
            select(Session).where(Session.refresh_token_hash == token_hash)
        )
        session = result.scalar_one_or_none()

        if session is None:
            raise SessionNotFoundError("Refresh token not found")

        if session.is_revoked:
            raise SessionRevokedError("Session has been revoked")

        if session.refresh_expires_at and datetime.now(UTC) > session.refresh_expires_at:
            raise SessionExpiredError("Refresh token has expired")

        # Generate new tokens
        new_access_token = self._generate_token()
        new_access_hash = self._hash_token(new_access_token)
        new_refresh_token = self._generate_token()
        new_refresh_hash = self._hash_token(new_refresh_token)

        now = datetime.now(UTC)
        new_expires_at = now + self._session_duration
        new_refresh_expires_at = now + self._refresh_duration

        # Update device info if provided
        update_values = {
            "token_hash": new_access_hash,
            "refresh_token_hash": new_refresh_hash,
            "expires_at": new_expires_at,
            "refresh_expires_at": new_refresh_expires_at,
            "last_activity_at": now,
            "updated_at": now,
        }

        if device_info:
            if device_info.ip_address:
                update_values["ip_address"] = device_info.ip_address
            if device_info.user_agent:
                update_values["user_agent"] = device_info.user_agent

        await self._db.execute(
            update(Session).where(Session.session_id == session.session_id).values(**update_values)
        )

        logger.info(
            "Session refreshed: session_id=%s",
            session.session_id,
        )

        return SessionToken(
            session_id=session.session_id,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_at=new_expires_at,
            refresh_expires_at=new_refresh_expires_at,
        )

    async def revoke_session(
        self,
        session_id: UUID,
        *,
        revoked_by: UUID | None = None,
        reason: str | None = None,
    ) -> bool:
        """Revoke a specific session.

        Args:
            session_id: ID of the session to revoke.
            revoked_by: ID of the user performing the revocation.
            reason: Reason for revocation (for audit).

        Returns:
            True if the session was revoked, False if not found.
        """
        from qerds.db.models.session import Session

        now = datetime.now(UTC)
        result = await self._db.execute(
            update(Session)
            .where(Session.session_id == session_id)
            .where(Session.revoked_at.is_(None))
            .values(
                is_active=False,
                revoked_at=now,
                revoked_by=revoked_by,
                revocation_reason=reason,
                updated_at=now,
            )
        )

        if result.rowcount > 0:
            logger.info(
                "Session revoked: session_id=%s, by=%s, reason=%s",
                session_id,
                revoked_by,
                reason,
            )
            return True

        return False

    async def revoke_all_user_sessions(
        self,
        *,
        admin_user_id: UUID | None = None,
        api_client_id: UUID | None = None,
        party_id: UUID | None = None,
        revoked_by: UUID | None = None,
        reason: str | None = None,
        exclude_session_id: UUID | None = None,
    ) -> int:
        """Revoke all sessions for a user.

        Exactly one of admin_user_id, api_client_id, or party_id must be provided.

        Args:
            admin_user_id: ID of the admin user whose sessions to revoke.
            api_client_id: ID of the API client whose sessions to revoke.
            party_id: ID of the party whose sessions to revoke.
            revoked_by: ID of the user performing the revocation.
            reason: Reason for revocation (for audit).
            exclude_session_id: Optional session ID to exclude (e.g., current session).

        Returns:
            Number of sessions revoked.

        Raises:
            ValueError: If zero or multiple principal IDs are provided.
        """
        from qerds.db.models.session import Session

        # Validate exactly one principal ID is provided
        principal_count = sum(1 for x in [admin_user_id, api_client_id, party_id] if x is not None)
        if principal_count != 1:
            raise ValueError(
                "Exactly one of admin_user_id, api_client_id, or party_id must be provided"
            )

        now = datetime.now(UTC)

        # Build the query based on principal type
        query = (
            update(Session)
            .where(Session.revoked_at.is_(None))
            .values(
                is_active=False,
                revoked_at=now,
                revoked_by=revoked_by,
                revocation_reason=reason,
                updated_at=now,
            )
        )

        if admin_user_id:
            query = query.where(Session.admin_user_id == admin_user_id)
            principal_id = admin_user_id
        elif api_client_id:
            query = query.where(Session.api_client_id == api_client_id)
            principal_id = api_client_id
        else:
            query = query.where(Session.party_id == party_id)
            principal_id = party_id

        if exclude_session_id:
            query = query.where(Session.session_id != exclude_session_id)

        result = await self._db.execute(query)
        count = result.rowcount

        if count > 0:
            logger.info(
                "All sessions revoked: principal=%s, count=%d, by=%s, reason=%s",
                principal_id,
                count,
                revoked_by,
                reason,
            )

        return count

    async def get_session(self, session_id: UUID) -> Session | None:
        """Get a session by ID.

        Args:
            session_id: ID of the session to retrieve.

        Returns:
            The Session object if found, None otherwise.
        """
        from qerds.db.models.session import Session

        result = await self._db.execute(select(Session).where(Session.session_id == session_id))
        return result.scalar_one_or_none()

    async def get_user_sessions(
        self,
        *,
        admin_user_id: UUID | None = None,
        api_client_id: UUID | None = None,
        party_id: UUID | None = None,
        active_only: bool = True,
        current_session_id: UUID | None = None,
    ) -> list[SessionInfo]:
        """Get all sessions for a user.

        Args:
            admin_user_id: ID of the admin user.
            api_client_id: ID of the API client.
            party_id: ID of the party.
            active_only: Only return active sessions.
            current_session_id: Optional current session ID (for marking).

        Returns:
            List of SessionInfo objects.
        """
        from qerds.db.models.session import Session

        # Build query
        query = select(Session)

        if admin_user_id:
            query = query.where(Session.admin_user_id == admin_user_id)
        elif api_client_id:
            query = query.where(Session.api_client_id == api_client_id)
        elif party_id:
            query = query.where(Session.party_id == party_id)
        else:
            return []

        if active_only:
            query = query.where(Session.is_active == True)  # noqa: E712
            query = query.where(Session.revoked_at.is_(None))
            query = query.where(Session.expires_at > datetime.now(UTC))

        query = query.order_by(Session.created_at.desc())

        result = await self._db.execute(query)
        sessions = result.scalars().all()

        return [
            SessionInfo(
                session_id=s.session_id,
                session_type=s.session_type,
                principal_id=s.get_principal_id(),
                principal_type=s.get_principal_type(),
                created_at=s.created_at,
                expires_at=s.expires_at,
                last_activity_at=s.last_activity_at,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                is_active=s.is_valid,
                is_current=s.session_id == current_session_id,
            )
            for s in sessions
        ]

    async def cleanup_expired_sessions(
        self,
        *,
        older_than_days: int = 30,
    ) -> int:
        """Delete expired sessions older than the specified number of days.

        This is a maintenance operation to clean up old session records.

        Args:
            older_than_days: Delete sessions expired more than this many days ago.

        Returns:
            Number of sessions deleted.
        """
        from qerds.db.models.session import Session

        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)

        result = await self._db.execute(delete(Session).where(Session.expires_at < cutoff))

        count = result.rowcount
        if count > 0:
            logger.info("Cleaned up %d expired sessions older than %d days", count, older_than_days)

        return count

    def _generate_token(self) -> str:
        """Generate a cryptographically secure token.

        Returns:
            URL-safe base64-encoded token string.
        """
        return secrets.token_urlsafe(SESSION_TOKEN_BYTES)

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage.

        Uses SHA-256 for token hashing. The hash is stored in the database
        instead of the plain token to prevent exposure if the database
        is compromised.

        Args:
            token: The token to hash.

        Returns:
            Hex-encoded SHA-256 hash (64 characters).
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _compare_tokens(self, token_a: str, token_b: str) -> bool:
        """Compare two tokens in constant time.

        Uses hmac.compare_digest to prevent timing attacks.

        Args:
            token_a: First token.
            token_b: Second token.

        Returns:
            True if tokens match, False otherwise.
        """
        return hmac.compare_digest(token_a.encode("utf-8"), token_b.encode("utf-8"))
