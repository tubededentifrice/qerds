"""Operations event logging for REQ-H05 change management.

Provides specialized logging for operations-relevant events:
- Configuration changes
- Deployment markers
- System maintenance events

All operations events are logged to the tamper-evident audit log (OPS stream)
using the underlying AuditLogService, ensuring immutability and integrity.

Note: Some events (like config changes) are also logged to the SECURITY stream
via SecurityEventLogger for security audit purposes. This service logs the
same events to OPS stream for change management compliance.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import AuditEventType, AuditLogEntry, AuditLogService

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Keys that should have their values redacted in audit logs
SENSITIVE_CONFIG_KEYS = frozenset(
    {
        "secret",
        "password",
        "api_key",
        "apikey",
        "token",
        "credential",
        "private_key",
        "privatekey",
        "secret_key",
        "secretkey",
        "access_key",
        "accesskey",
        "auth_token",
        "authtoken",
        "database_url",
        "db_url",
        "dsn",
        "connection_string",
    }
)

# Patterns that indicate a sensitive key
SENSITIVE_KEY_PATTERNS = (
    re.compile(r".*secret.*", re.IGNORECASE),
    re.compile(r".*password.*", re.IGNORECASE),
    re.compile(r".*_key$", re.IGNORECASE),
    re.compile(r".*token.*", re.IGNORECASE),
    re.compile(r".*credential.*", re.IGNORECASE),
)

REDACTED_VALUE = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Check if a configuration key is sensitive and should be redacted.

    Args:
        key: The configuration key to check.

    Returns:
        True if the key is sensitive and values should be redacted.
    """
    key_lower = key.lower()

    # Check explicit list
    if key_lower in SENSITIVE_CONFIG_KEYS:
        return True

    # Check patterns
    return any(pattern.match(key_lower) for pattern in SENSITIVE_KEY_PATTERNS)


def redact_if_sensitive(key: str, value: str | None) -> str | None:
    """Redact a value if its key is sensitive.

    Args:
        key: The configuration key.
        value: The value to potentially redact.

    Returns:
        The original value or REDACTED_VALUE if sensitive.
    """
    if value is None:
        return None
    if is_sensitive_key(key):
        return REDACTED_VALUE
    return value


@dataclass(frozen=True, slots=True)
class OpsActor:
    """Represents the actor performing an operations action.

    Attributes:
        actor_id: Unique identifier (user ID, CI system, etc.).
        actor_type: Type of actor (admin, system, ci_pipeline).
    """

    actor_id: str
    actor_type: str


@dataclass(frozen=True, slots=True)
class DeploymentInfo:
    """Information about a deployment event.

    Attributes:
        version: Application version being deployed.
        git_sha: Git commit SHA.
        deployer: Identity of deployer.
        environment: Target environment.
        details: Additional deployment metadata.
        timestamp: When deployment occurred.
    """

    version: str
    git_sha: str
    deployer: str
    environment: str = "production"
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "version": self.version,
            "git_sha": self.git_sha,
            "deployer": self.deployer,
            "environment": self.environment,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ConfigChangeInfo:
    """Information about a configuration change event.

    Attributes:
        config_key: The configuration setting that changed.
        old_value: Previous value (redacted if sensitive).
        new_value: New value (redacted if sensitive).
        change_type: Type of change (create, update, delete).
        is_sensitive: Whether values were redacted.
        details: Additional change context.
        timestamp: When change occurred.
    """

    config_key: str
    old_value: str | None = None
    new_value: str | None = None
    change_type: str = "update"
    is_sensitive: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "config_key": self.config_key,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "change_type": self.change_type,
            "is_sensitive": self.is_sensitive,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


class OpsEventLogger:
    """High-level API for logging operations events.

    This service wraps AuditLogService to provide a specialized interface
    for operations event logging to the OPS audit stream. Used for change
    management compliance (REQ-H05).

    Example:
        logger = OpsEventLogger(session)

        # Log a deployment marker
        await logger.log_deployment_marker(
            actor=OpsActor(actor_id="github-actions", actor_type="ci_pipeline"),
            deployment=DeploymentInfo(
                version="v1.2.3",
                git_sha="abc1234",
                deployer="github-actions",
                environment="production",
            ),
        )

        # Log a config change
        await logger.log_config_change(
            actor=OpsActor(actor_id="admin-123", actor_type="admin"),
            config_key="max_delivery_size_mb",
            old_value="100",
            new_value="200",
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the operations event logger.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._audit_service = AuditLogService(session)

    async def log_deployment_marker(
        self,
        *,
        actor: OpsActor,
        deployment: DeploymentInfo,
    ) -> AuditLogEntry:
        """Log a deployment marker event.

        Called by CI/CD pipelines after deployment to create an audit
        record for change management compliance.

        Args:
            actor: The actor (usually CI system) recording the deployment.
            deployment: Deployment information.

        Returns:
            The created audit log entry.
        """
        summary = {
            "version": deployment.version,
            "git_sha": deployment.git_sha[:7],  # Short SHA for summary
            "deployer": deployment.deployer,
            "environment": deployment.environment,
        }

        entry = await self._audit_service.append(
            stream=AuditStream.OPS,
            event_type=AuditEventType.DEPLOYMENT_MARKER,
            payload=deployment.to_dict(),
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
            resource_type="deployment",
            resource_id=deployment.version,
            summary=summary,
        )

        logger.info(
            "Deployment marker logged",
            extra={
                "version": deployment.version,
                "git_sha": deployment.git_sha,
                "deployer": deployment.deployer,
                "environment": deployment.environment,
            },
        )

        return entry

    async def log_config_change(
        self,
        *,
        actor: OpsActor,
        config_key: str,
        old_value: str | None = None,
        new_value: str | None = None,
        change_type: str = "update",
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log a configuration change event.

        Automatically redacts sensitive values based on the config key.

        Args:
            actor: The actor making the change.
            config_key: The configuration setting that changed.
            old_value: Previous value (will be redacted if sensitive).
            new_value: New value (will be redacted if sensitive).
            change_type: Type of change (create, update, delete).
            details: Additional change context.

        Returns:
            The created audit log entry.
        """
        # Check if key is sensitive and redact values if needed
        sensitive = is_sensitive_key(config_key)
        redacted_old = redact_if_sensitive(config_key, old_value)
        redacted_new = redact_if_sensitive(config_key, new_value)

        change_info = ConfigChangeInfo(
            config_key=config_key,
            old_value=redacted_old,
            new_value=redacted_new,
            change_type=change_type,
            is_sensitive=sensitive,
            details=details or {},
        )

        summary = {
            "config_key": config_key,
            "change_type": change_type,
            "is_sensitive": sensitive,
        }

        entry = await self._audit_service.append(
            stream=AuditStream.OPS,
            event_type=AuditEventType.CONFIG_CHANGED,
            payload=change_info.to_dict(),
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
            resource_type="config",
            resource_id=config_key,
            summary=summary,
        )

        logger.debug(
            "Config change logged to OPS stream",
            extra={
                "config_key": config_key,
                "change_type": change_type,
                "is_sensitive": sensitive,
            },
        )

        return entry

    async def log_config_snapshot(
        self,
        *,
        actor: OpsActor,
        snapshot_id: uuid.UUID,
        version: str,
        description: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Log a configuration snapshot creation event.

        Args:
            actor: The actor creating the snapshot.
            snapshot_id: ID of the created snapshot.
            version: Version identifier of the snapshot.
            description: Description of changes.
            details: Additional snapshot metadata.

        Returns:
            The created audit log entry.
        """
        payload = {
            "snapshot_id": str(snapshot_id),
            "version": version,
            "description": description,
            "details": details or {},
            "timestamp": datetime.now(UTC).isoformat(),
        }

        summary = {
            "version": version,
            "snapshot_id": str(snapshot_id)[:8],
        }

        entry = await self._audit_service.append(
            stream=AuditStream.OPS,
            event_type=AuditEventType.CONFIG_SNAPSHOT,
            payload=payload,
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
            resource_type="config_snapshot",
            resource_id=str(snapshot_id),
            summary=summary,
        )

        logger.info(
            "Config snapshot logged to OPS stream",
            extra={
                "snapshot_id": str(snapshot_id),
                "version": version,
            },
        )

        return entry


def create_ci_actor(
    system_name: str = "ci_pipeline",
    pipeline_id: str | None = None,
) -> OpsActor:
    """Create an OpsActor for CI/CD pipeline events.

    Args:
        system_name: Name of the CI system (github-actions, gitlab-ci, etc.).
        pipeline_id: Optional pipeline/job ID.

    Returns:
        OpsActor representing the CI system.
    """
    actor_id = system_name
    if pipeline_id:
        actor_id = f"{system_name}:{pipeline_id}"
    return OpsActor(actor_id=actor_id, actor_type="ci_pipeline")


def create_admin_actor(user_id: str) -> OpsActor:
    """Create an OpsActor for admin-initiated operations.

    Args:
        user_id: Admin user ID.

    Returns:
        OpsActor representing the admin.
    """
    return OpsActor(actor_id=user_id, actor_type="admin")
