"""Security event logging for REQ-D08.

Provides specialized logging for security-relevant events:
- Authentication attempts (success/failure)
- Authorization decisions
- Admin actions
- Key operations
- Configuration changes
- Access to sensitive data

All security events are logged to the tamper-evident audit log (SECURITY stream)
using the underlying AuditLogService, ensuring immutability and integrity.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import AuditEventType, AuditLogEntry, AuditLogService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class SecurityEventType(str, Enum):
    """Security event types for structured logging.

    These map to specific security-relevant actions that must be tracked
    for compliance and incident investigation.
    """

    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_LOGOUT = "auth_logout"
    AUTH_TOKEN_REFRESH = "auth_token_refresh"  # noqa: S105 - not a password
    AUTH_MFA_CHALLENGE = "auth_mfa_challenge"
    AUTH_MFA_SUCCESS = "auth_mfa_success"
    AUTH_MFA_FAILURE = "auth_mfa_failure"
    AUTH_SESSION_EXPIRED = "auth_session_expired"

    # Authorization events
    AUTHZ_GRANTED = "authz_granted"
    AUTHZ_DENIED = "authz_denied"
    AUTHZ_ELEVATED = "authz_elevated"  # Privilege escalation (legitimate)

    # Admin actions
    ADMIN_ACTION = "admin_action"
    ADMIN_USER_CREATED = "admin_user_created"
    ADMIN_USER_MODIFIED = "admin_user_modified"
    ADMIN_USER_DISABLED = "admin_user_disabled"
    ADMIN_ROLE_ASSIGNED = "admin_role_assigned"
    ADMIN_ROLE_REVOKED = "admin_role_revoked"

    # Key operations
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    KEY_EXPORTED = "key_exported"
    KEY_IMPORTED = "key_imported"

    # Configuration changes
    CONFIG_CHANGED = "config_changed"
    CONFIG_ROLLBACK = "config_rollback"

    # Sensitive data access
    SENSITIVE_ACCESS = "sensitive_access"
    SENSITIVE_EXPORT = "sensitive_export"
    EVIDENCE_ACCESSED = "evidence_accessed"
    AUDIT_LOG_ACCESSED = "audit_log_accessed"

    # Dual-control operations
    DUAL_CONTROL_REQUESTED = "dual_control_requested"
    DUAL_CONTROL_APPROVED = "dual_control_approved"
    DUAL_CONTROL_REJECTED = "dual_control_rejected"


class AuthOutcome(str, Enum):
    """Outcome of an authentication attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    LOCKED = "locked"  # Account locked after failures
    EXPIRED = "expired"  # Credentials expired
    MFA_REQUIRED = "mfa_required"


class AuthzOutcome(str, Enum):
    """Outcome of an authorization decision."""

    GRANTED = "granted"
    DENIED = "denied"
    ELEVATED = "elevated"  # Access granted with elevated privileges


@dataclass(frozen=True, slots=True)
class SecurityActor:
    """Represents the actor performing a security-relevant action.

    Attributes:
        actor_id: Unique identifier (user ID, client ID, system ID).
        actor_type: Type of actor (user, api_client, system, admin).
        ip_address: IP address of the request origin.
        user_agent: User agent string (for web requests).
        session_id: Session identifier if applicable.
    """

    actor_id: str
    actor_type: str
    ip_address: str | None = None
    user_agent: str | None = None
    session_id: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEventPayload:
    """Structured payload for security events.

    Provides a consistent structure for all security event details,
    enabling easier querying and analysis.

    Attributes:
        event_type: The specific type of security event.
        actor: The actor performing the action.
        action: Description of the action performed.
        resource_type: Type of resource being acted upon.
        resource_id: Identifier of the resource.
        outcome: Result of the action (success, failure, etc.).
        details: Additional event-specific details.
        timestamp: When the event occurred.
    """

    event_type: SecurityEventType
    actor: SecurityActor
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert payload to dictionary for storage."""
        return {
            "event_type": self.event_type.value,
            "actor": {
                "actor_id": self.actor.actor_id,
                "actor_type": self.actor.actor_type,
                "ip_address": self.actor.ip_address,
                "user_agent": self.actor.user_agent,
                "session_id": self.actor.session_id,
            },
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "outcome": self.outcome,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class SecurityEventLogger:
    """High-level API for logging security events.

    This service wraps AuditLogService to provide a specialized interface
    for security event logging with:
    - Structured payloads
    - Type-safe event types
    - Convenience methods for common events
    - Automatic actor context capture

    All events are logged to the SECURITY audit stream with full
    tamper-evidence (hash chains).

    Example:
        logger = SecurityEventLogger(session)

        # Log authentication attempt
        await logger.log_auth_event(
            actor=SecurityActor(actor_id="user-123", actor_type="user", ip_address="192.168.1.1"),
            outcome=AuthOutcome.SUCCESS,
            method="password",
            details={"mfa_used": True},
        )

        # Log authorization decision
        await logger.log_authz_event(
            actor=SecurityActor(actor_id="user-123", actor_type="user"),
            permission="view_delivery",
            resource_type="delivery",
            resource_id="del-456",
            outcome=AuthzOutcome.GRANTED,
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the security event logger.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._audit_service = AuditLogService(session)

    async def log_event(
        self,
        payload: SecurityEventPayload,
    ) -> AuditLogEntry:
        """Log a generic security event.

        This is the base method used by all specialized logging methods.
        It converts the payload to the audit log format and appends
        to the SECURITY stream.

        Args:
            payload: The security event payload.

        Returns:
            The created audit log entry.
        """
        # Map SecurityEventType to AuditEventType where possible
        audit_event_type = self._map_to_audit_event_type(payload.event_type)

        # Create summary for quick display without loading full payload
        summary = {
            "action": payload.action,
            "outcome": payload.outcome,
        }
        if payload.resource_type:
            summary["resource"] = f"{payload.resource_type}/{payload.resource_id}"

        entry = await self._audit_service.append(
            stream=AuditStream.SECURITY,
            event_type=audit_event_type,
            payload=payload.to_dict(),
            actor_type=payload.actor.actor_type,
            actor_id=payload.actor.actor_id,
            resource_type=payload.resource_type,
            resource_id=payload.resource_id,
            summary=summary,
        )

        logger.debug(
            "Security event logged: %s by %s (%s)",
            payload.event_type.value,
            payload.actor.actor_id,
            payload.outcome or "no outcome",
        )

        return entry

    async def log_auth_event(
        self,
        *,
        actor: SecurityActor,
        outcome: AuthOutcome,
        method: str = "password",
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log an authentication event.

        Args:
            actor: The actor attempting authentication.
            outcome: The authentication outcome.
            method: Authentication method used (password, token, mfa, etc.).
            details: Additional details (e.g., failure reason).

        Returns:
            The created audit log entry.
        """
        # Determine event type based on outcome
        if outcome == AuthOutcome.SUCCESS:
            event_type = SecurityEventType.AUTH_SUCCESS
        elif outcome == AuthOutcome.FAILURE:
            event_type = SecurityEventType.AUTH_FAILURE
        elif outcome == AuthOutcome.MFA_REQUIRED:
            event_type = SecurityEventType.AUTH_MFA_CHALLENGE
        else:
            # LOCKED or EXPIRED are still failures
            event_type = SecurityEventType.AUTH_FAILURE

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"authenticate via {method}",
            resource_type="session",
            outcome=outcome.value,
            details={
                "method": method,
                **(details or {}),
            },
        )

        return await self.log_event(payload)

    async def log_auth_logout(
        self,
        *,
        actor: SecurityActor,
        session_id: str | None = None,
        reason: str = "user_initiated",
    ) -> AuditLogEntry:
        """Log a logout event.

        Args:
            actor: The actor logging out.
            session_id: The session being terminated.
            reason: Reason for logout (user_initiated, timeout, forced).

        Returns:
            The created audit log entry.
        """
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_LOGOUT,
            actor=actor,
            action="logout",
            resource_type="session",
            resource_id=session_id,
            outcome="success",
            details={"reason": reason},
        )

        return await self.log_event(payload)

    async def log_authz_event(
        self,
        *,
        actor: SecurityActor,
        permission: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: AuthzOutcome,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log an authorization decision.

        Args:
            actor: The actor requesting authorization.
            permission: The permission being checked.
            resource_type: Type of resource being accessed.
            resource_id: ID of the resource being accessed.
            outcome: The authorization outcome.
            details: Additional details (e.g., denial reason).

        Returns:
            The created audit log entry.
        """
        if outcome == AuthzOutcome.GRANTED:
            event_type = SecurityEventType.AUTHZ_GRANTED
        elif outcome == AuthzOutcome.DENIED:
            event_type = SecurityEventType.AUTHZ_DENIED
        else:
            event_type = SecurityEventType.AUTHZ_ELEVATED

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"check permission: {permission}",
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome.value,
            details={
                "permission": permission,
                **(details or {}),
            },
        )

        return await self.log_event(payload)

    async def log_admin_action(
        self,
        *,
        actor: SecurityActor,
        action: str,
        target_type: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log an administrative action.

        Args:
            actor: The admin performing the action.
            action: Description of the admin action.
            target_type: Type of entity being modified.
            target_id: ID of the entity being modified.
            details: Additional action details.

        Returns:
            The created audit log entry.
        """
        payload = SecurityEventPayload(
            event_type=SecurityEventType.ADMIN_ACTION,
            actor=actor,
            action=action,
            resource_type=target_type,
            resource_id=target_id,
            outcome="completed",
            details=details or {},
        )

        return await self.log_event(payload)

    async def log_user_management(
        self,
        *,
        actor: SecurityActor,
        action: str,
        target_user_id: str,
        changes: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log user management actions (create, modify, disable).

        Args:
            actor: The admin performing the action.
            action: Action type (create, modify, disable).
            target_user_id: ID of the user being managed.
            changes: Details of what changed.

        Returns:
            The created audit log entry.
        """
        # Select specific event type based on action
        event_type_map = {
            "create": SecurityEventType.ADMIN_USER_CREATED,
            "modify": SecurityEventType.ADMIN_USER_MODIFIED,
            "disable": SecurityEventType.ADMIN_USER_DISABLED,
        }
        event_type = event_type_map.get(action, SecurityEventType.ADMIN_ACTION)

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"user management: {action}",
            resource_type="user",
            resource_id=target_user_id,
            outcome="completed",
            details={"changes": changes} if changes else {},
        )

        return await self.log_event(payload)

    async def log_role_change(
        self,
        *,
        actor: SecurityActor,
        target_user_id: str,
        role: str,
        action: str,  # "assign" or "revoke"
    ) -> AuditLogEntry:
        """Log role assignment or revocation.

        Args:
            actor: The admin performing the action.
            target_user_id: ID of the user whose role is changing.
            role: The role being assigned or revoked.
            action: "assign" or "revoke".

        Returns:
            The created audit log entry.
        """
        if action == "assign":
            event_type = SecurityEventType.ADMIN_ROLE_ASSIGNED
        else:
            event_type = SecurityEventType.ADMIN_ROLE_REVOKED

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"role {action}: {role}",
            resource_type="user",
            resource_id=target_user_id,
            outcome="completed",
            details={"role": role, "action": action},
        )

        return await self.log_event(payload)

    async def log_key_operation(
        self,
        *,
        actor: SecurityActor,
        operation: str,
        key_id: str | None = None,
        key_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log cryptographic key operations.

        Args:
            actor: The actor performing the operation.
            operation: Operation type (generate, rotate, revoke, export, import).
            key_id: Identifier of the key (may be None for generation).
            key_type: Type of key (signing, encryption, etc.).
            details: Additional operation details.

        Returns:
            The created audit log entry.
        """
        event_type_map = {
            "generate": SecurityEventType.KEY_GENERATED,
            "rotate": SecurityEventType.KEY_ROTATED,
            "revoke": SecurityEventType.KEY_REVOKED,
            "export": SecurityEventType.KEY_EXPORTED,
            "import": SecurityEventType.KEY_IMPORTED,
        }
        event_type = event_type_map.get(operation, SecurityEventType.KEY_GENERATED)

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"key operation: {operation}",
            resource_type="key",
            resource_id=key_id,
            outcome="completed",
            details={
                "operation": operation,
                "key_type": key_type,
                **(details or {}),
            },
        )

        return await self.log_event(payload)

    async def log_config_change(
        self,
        *,
        actor: SecurityActor,
        config_key: str,
        old_value: str | None = None,
        new_value: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log configuration changes.

        Note: Sensitive values should be masked before logging.

        Args:
            actor: The actor making the change.
            config_key: The configuration key being changed.
            old_value: Previous value (masked if sensitive).
            new_value: New value (masked if sensitive).
            details: Additional context.

        Returns:
            The created audit log entry.
        """
        payload = SecurityEventPayload(
            event_type=SecurityEventType.CONFIG_CHANGED,
            actor=actor,
            action=f"config change: {config_key}",
            resource_type="config",
            resource_id=config_key,
            outcome="completed",
            details={
                "config_key": config_key,
                "old_value": old_value,
                "new_value": new_value,
                **(details or {}),
            },
        )

        return await self.log_event(payload)

    async def log_sensitive_access(
        self,
        *,
        actor: SecurityActor,
        resource_type: str,
        resource_id: str,
        access_type: str = "read",
        purpose: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log access to sensitive data.

        Args:
            actor: The actor accessing the data.
            resource_type: Type of sensitive resource.
            resource_id: ID of the resource being accessed.
            access_type: Type of access (read, export, download).
            purpose: Stated purpose for the access (for compliance).
            details: Additional context.

        Returns:
            The created audit log entry.
        """
        # Use specific event type for known resources
        if resource_type == "evidence":
            event_type = SecurityEventType.EVIDENCE_ACCESSED
        elif resource_type == "audit_log":
            event_type = SecurityEventType.AUDIT_LOG_ACCESSED
        elif access_type == "export":
            event_type = SecurityEventType.SENSITIVE_EXPORT
        else:
            event_type = SecurityEventType.SENSITIVE_ACCESS

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"{access_type} sensitive data",
            resource_type=resource_type,
            resource_id=resource_id,
            outcome="accessed",
            details={
                "access_type": access_type,
                "purpose": purpose,
                **(details or {}),
            },
        )

        return await self.log_event(payload)

    async def log_dual_control_request(
        self,
        *,
        actor: SecurityActor,
        request_id: str,
        operation: str,
        permission: str,
        reason: str,
    ) -> AuditLogEntry:
        """Log a dual-control request creation.

        Args:
            actor: The actor making the request.
            request_id: Unique ID of the dual-control request.
            operation: The operation requiring approval.
            permission: The permission being requested.
            reason: Justification for the request.

        Returns:
            The created audit log entry.
        """
        payload = SecurityEventPayload(
            event_type=SecurityEventType.DUAL_CONTROL_REQUESTED,
            actor=actor,
            action=f"dual-control request: {operation}",
            resource_type="dual_control_request",
            resource_id=request_id,
            outcome="pending",
            details={
                "operation": operation,
                "permission": permission,
                "reason": reason,
            },
        )

        return await self.log_event(payload)

    async def log_dual_control_decision(
        self,
        *,
        actor: SecurityActor,
        request_id: str,
        decision: str,  # "approve" or "reject"
        reason: str | None = None,
    ) -> AuditLogEntry:
        """Log a dual-control approval or rejection.

        Args:
            actor: The actor making the decision.
            request_id: ID of the dual-control request.
            decision: "approve" or "reject".
            reason: Reason for rejection (if applicable).

        Returns:
            The created audit log entry.
        """
        if decision == "approve":
            event_type = SecurityEventType.DUAL_CONTROL_APPROVED
        else:
            event_type = SecurityEventType.DUAL_CONTROL_REJECTED

        payload = SecurityEventPayload(
            event_type=event_type,
            actor=actor,
            action=f"dual-control {decision}",
            resource_type="dual_control_request",
            resource_id=request_id,
            outcome=decision,
            details={"reason": reason} if reason else {},
        )

        return await self.log_event(payload)

    async def get_events(
        self,
        *,
        event_type: SecurityEventType | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        start_seq: int | None = None,
        end_seq: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Query security events with filtering.

        Args:
            event_type: Filter by specific event type.
            actor_id: Filter by actor identifier.
            resource_type: Filter by resource type.
            resource_id: Filter by resource identifier.
            start_seq: Minimum sequence number.
            end_seq: Maximum sequence number.
            limit: Maximum number of records.
            offset: Number of records to skip.

        Returns:
            List of matching audit log entries.
        """
        event_type_str = None
        if event_type is not None:
            # Map to audit event type string
            event_type_str = self._map_to_audit_event_type(event_type)

        return await self._audit_service.get_records(
            stream=AuditStream.SECURITY,
            event_type=event_type_str,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            start_seq=start_seq,
            end_seq=end_seq,
            limit=limit,
            offset=offset,
        )

    async def export_events(
        self,
        *,
        start_seq: int | None = None,
        end_seq: int | None = None,
        include_verification: bool = True,
    ) -> dict[str, Any]:
        """Export security events for audit.

        Args:
            start_seq: Starting sequence number.
            end_seq: Ending sequence number.
            include_verification: Include chain verification result.

        Returns:
            Export package with events and optional verification.
        """
        events = await self._audit_service.get_records(
            stream=AuditStream.SECURITY,
            start_seq=start_seq,
            end_seq=end_seq,
            limit=10000,  # Large limit for export
        )

        result: dict[str, Any] = {
            "stream": AuditStream.SECURITY.value,
            "exported_at": datetime.now(UTC).isoformat(),
            "record_count": len(events),
            "events": [
                {
                    "record_id": str(e.record_id),
                    "seq_no": e.seq_no,
                    "event_type": e.event_type,
                    "actor_type": e.actor_type,
                    "actor_id": e.actor_id,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "record_hash": e.record_hash,
                    "prev_record_hash": e.prev_record_hash,
                    "created_at": e.created_at.isoformat(),
                    "summary": e.summary,
                }
                for e in events
            ],
        }

        if include_verification and events:
            verification = await self._audit_service.verify_chain(
                AuditStream.SECURITY,
                start_seq=start_seq,
                end_seq=end_seq,
            )
            result["verification"] = {
                "valid": verification.valid,
                "checked_records": verification.checked_records,
                "first_seq_no": verification.first_seq_no,
                "last_seq_no": verification.last_seq_no,
                "errors": verification.errors,
            }

        return result

    def _map_to_audit_event_type(self, event_type: SecurityEventType) -> str:
        """Map SecurityEventType to AuditEventType string.

        Uses the AuditEventType where a direct mapping exists,
        otherwise uses the SecurityEventType value directly.

        Args:
            event_type: The security event type.

        Returns:
            String event type for the audit log.
        """
        # Direct mappings to existing AuditEventType
        mapping = {
            SecurityEventType.AUTH_SUCCESS: AuditEventType.AUTH_LOGIN.value,
            SecurityEventType.AUTH_FAILURE: AuditEventType.AUTH_FAILED.value,
            SecurityEventType.AUTH_LOGOUT: AuditEventType.AUTH_LOGOUT.value,
            SecurityEventType.AUTH_MFA_CHALLENGE: AuditEventType.AUTH_MFA_CHALLENGE.value,
            SecurityEventType.AUTHZ_GRANTED: AuditEventType.AUTHZ_GRANTED.value,
            SecurityEventType.AUTHZ_DENIED: AuditEventType.AUTHZ_DENIED.value,
            SecurityEventType.ADMIN_ACTION: AuditEventType.ADMIN_ACTION.value,
            SecurityEventType.KEY_GENERATED: AuditEventType.KEY_GENERATED.value,
            SecurityEventType.KEY_ROTATED: AuditEventType.KEY_ROTATED.value,
            SecurityEventType.KEY_REVOKED: AuditEventType.KEY_REVOKED.value,
            SecurityEventType.CONFIG_CHANGED: AuditEventType.CONFIG_CHANGED.value,
        }

        return mapping.get(event_type, event_type.value)


def create_system_actor(
    component: str = "system",
    ip_address: str = "127.0.0.1",
) -> SecurityActor:
    """Create a SecurityActor for system-initiated events.

    Args:
        component: Name of the system component.
        ip_address: IP address (defaults to localhost).

    Returns:
        SecurityActor representing the system.
    """
    return SecurityActor(
        actor_id=f"system:{component}",
        actor_type="system",
        ip_address=ip_address,
    )
