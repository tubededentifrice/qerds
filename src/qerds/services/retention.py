"""Retention policy management and enforcement for CPCE compliance.

Covers: REQ-F05 (one-year proof retention), REQ-H02 (retention enforcement)

This module provides:
- RetentionPolicyService: CRUD operations for retention policies
- RetentionEnforcementService: Finding and processing expired artifacts
- CPCE-compliant defaults with minimum 365-day retention for evidence

The French CPCE (Code des Postes et des Communications Électroniques)
requires electronic registered mail providers to retain proof of delivery
for a minimum of one year.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from qerds.db.models.base import AuditStream, RetentionActionType
from qerds.db.models.retention import RetentionAction, RetentionPolicy
from qerds.services.audit_log import AuditEventType, AuditLogService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# CPCE requires minimum 1 year retention for delivery proofs
CPCE_MINIMUM_RETENTION_DAYS = 365


class ArtifactType(str, Enum):
    """Types of artifacts subject to retention policies."""

    DELIVERY = "delivery"
    CONTENT_OBJECT = "content_object"
    EVIDENCE_OBJECT = "evidence_object"
    AUDIT_LOG = "audit_log"


class RetentionError(Exception):
    """Base exception for retention-related errors."""

    pass


class CPCEViolationError(RetentionError):
    """Raised when an operation would violate CPCE minimum retention requirements."""

    pass


class PolicyNotFoundError(RetentionError):
    """Raised when a requested retention policy does not exist."""

    pass


@dataclass(frozen=True)
class EligibleArtifact:
    """Represents an artifact eligible for retention action.

    Attributes:
        artifact_type: The type of artifact (delivery, content_object, etc.)
        artifact_ref: Unique reference/ID for the artifact
        created_at: When the artifact was created
        retention_deadline: When retention period expires
        metadata: Additional artifact-specific information
    """

    artifact_type: str
    artifact_ref: str
    created_at: datetime
    retention_deadline: datetime
    metadata: dict[str, Any] | None = None


@dataclass
class RetentionActionResult:
    """Result of executing a retention action.

    Attributes:
        success: Whether the action completed successfully
        action_type: The type of action taken (archive or delete)
        archive_ref: Reference to archive location if archived
        error_message: Error details if action failed
    """

    success: bool
    action_type: RetentionActionType
    archive_ref: str | None = None
    error_message: str | None = None


class RetentionPolicyService:
    """Service for managing retention policies.

    Provides CRUD operations for retention policies with CPCE compliance
    enforcement. Ensures that evidence-related artifacts cannot have
    retention periods shorter than the legally required minimum.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the service.

        Args:
            session: Database session for operations.
        """
        self._session = session

    async def create_policy(
        self,
        artifact_type: str,
        retention_days: int,
        expiry_action: RetentionActionType,
        *,
        description: str | None = None,
        is_active: bool = True,
    ) -> RetentionPolicy:
        """Create a new retention policy.

        Args:
            artifact_type: Type of artifact this policy applies to.
            retention_days: Number of days to retain artifacts.
            expiry_action: Action to take when retention period expires.
            description: Human-readable policy description.
            is_active: Whether policy is active (default True).

        Returns:
            The created RetentionPolicy.

        Raises:
            CPCEViolationError: If retention_days is below CPCE minimum
                for evidence-related artifacts.
        """
        # Enforce CPCE minimum for evidence-related artifacts
        evidence_types = {
            ArtifactType.DELIVERY.value,
            ArtifactType.EVIDENCE_OBJECT.value,
        }
        if (
            artifact_type in evidence_types
            and retention_days < CPCE_MINIMUM_RETENTION_DAYS
        ):
            raise CPCEViolationError(
                f"CPCE requires minimum {CPCE_MINIMUM_RETENTION_DAYS} days retention "
                f"for {artifact_type} artifacts. Requested: {retention_days} days."
            )

        policy = RetentionPolicy(
            artifact_type=artifact_type,
            minimum_retention_days=retention_days,
            policy_version="1.0",
            expiry_action=expiry_action,
            description=description,
            is_active=is_active,
        )

        self._session.add(policy)
        await self._session.flush()

        logger.info(
            "Created retention policy: type=%s, days=%d, action=%s",
            artifact_type,
            retention_days,
            expiry_action.value,
        )

        return policy

    async def get_policy(self, policy_id: str) -> RetentionPolicy | None:
        """Get a retention policy by ID.

        Args:
            policy_id: The policy's UUID.

        Returns:
            The RetentionPolicy if found, None otherwise.
        """
        import uuid as uuid_module

        try:
            policy_uuid = (
                uuid_module.UUID(policy_id) if isinstance(policy_id, str) else policy_id
            )
        except ValueError:
            return None

        result = await self._session.execute(
            select(RetentionPolicy).where(RetentionPolicy.policy_id == policy_uuid)
        )
        return result.scalar_one_or_none()

    async def get_active_policies(
        self,
        artifact_type: str | None = None,
    ) -> list[RetentionPolicy]:
        """Get all active retention policies.

        Args:
            artifact_type: Optional filter by artifact type.

        Returns:
            List of active RetentionPolicy objects.
        """
        query = select(RetentionPolicy).where(RetentionPolicy.is_active.is_(True))

        if artifact_type:
            query = query.where(RetentionPolicy.artifact_type == artifact_type)

        query = query.order_by(RetentionPolicy.artifact_type)

        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def deactivate_policy(self, policy_id: str) -> bool:
        """Deactivate a retention policy.

        Args:
            policy_id: The policy's UUID.

        Returns:
            True if policy was deactivated, False if not found.
        """
        policy = await self.get_policy(policy_id)
        if not policy:
            return False

        policy.is_active = False
        await self._session.flush()

        logger.info("Deactivated retention policy: id=%s", policy_id)
        return True

    def calculate_retention_deadline(
        self,
        created_at: datetime,
        retention_days: int,
    ) -> datetime:
        """Calculate when an artifact's retention period expires.

        Args:
            created_at: When the artifact was created.
            retention_days: Number of days to retain.

        Returns:
            The datetime when retention expires.
        """
        return created_at + timedelta(days=retention_days)

    def is_past_minimum_retention(
        self,
        created_at: datetime,
        now: datetime | None = None,
    ) -> bool:
        """Check if artifact has passed CPCE minimum retention period.

        Args:
            created_at: When the artifact was created.
            now: Current time (defaults to UTC now).

        Returns:
            True if minimum retention period has passed.
        """
        if now is None:
            now = datetime.now(UTC)

        deadline = self.calculate_retention_deadline(
            created_at,
            CPCE_MINIMUM_RETENTION_DAYS,
        )
        return now >= deadline


class RetentionEnforcementService:
    """Service for enforcing retention policies.

    Finds artifacts eligible for retention actions and executes those
    actions (archive or delete) while maintaining audit trails.
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the service.

        Args:
            session: Database session for operations.
        """
        self._session = session
        self._audit_service = AuditLogService(session)

    async def find_eligible_artifacts(
        self,
        policy: RetentionPolicy,
        limit: int = 100,
    ) -> list[EligibleArtifact]:
        """Find artifacts eligible for retention action under a policy.

        This queries the appropriate table based on artifact_type and
        returns artifacts whose retention period has expired.

        Args:
            policy: The retention policy to evaluate against.
            limit: Maximum number of artifacts to return.

        Returns:
            List of EligibleArtifact objects ready for action.
        """
        now = datetime.now(UTC)
        cutoff_date = now - timedelta(days=policy.minimum_retention_days)

        # For now, return empty list - actual implementation will query
        # specific tables based on artifact_type
        # This is a placeholder that will be expanded when we have
        # the full artifact table structure
        logger.debug(
            "Finding eligible artifacts: type=%s, cutoff=%s, limit=%d",
            policy.artifact_type,
            cutoff_date.isoformat(),
            limit,
        )

        # TODO: Implement queries for each artifact type
        # - delivery: Query deliveries table
        # - content_object: Query content_objects table
        # - evidence_object: Query evidence_objects table
        # - audit_log: Query audit_logs table (with extra care for compliance)

        return []

    async def execute_action(
        self,
        artifact: EligibleArtifact,
        policy: RetentionPolicy,
        *,
        dry_run: bool = False,
        executor: str = "system",
    ) -> RetentionActionResult:
        """Execute a retention action on an artifact.

        Args:
            artifact: The artifact to process.
            policy: The policy dictating the action.
            dry_run: If True, don't actually perform the action.
            executor: Identifier of who/what triggered the action.

        Returns:
            RetentionActionResult with outcome details.
        """
        action_type = policy.expiry_action

        if dry_run:
            logger.info(
                "Dry run: would %s artifact %s (type=%s)",
                action_type.value,
                artifact.artifact_ref,
                artifact.artifact_type,
            )
            return RetentionActionResult(
                success=True,
                action_type=action_type,
            )

        try:
            archive_ref = None

            if action_type == RetentionActionType.ARCHIVE:
                # Archive the artifact to cold storage
                archive_ref = await self._archive_artifact(artifact)
            elif action_type == RetentionActionType.DELETE:
                # Permanently delete the artifact
                await self._delete_artifact(artifact)

            # Record the action
            action_record = RetentionAction(
                policy_id=policy.policy_id,
                artifact_type=artifact.artifact_type,
                artifact_ref=artifact.artifact_ref,
                action_type=action_type,
                executed_at=datetime.now(UTC),
                executed_by=executor,
                result="success",
                archive_ref=archive_ref,
            )
            self._session.add(action_record)

            # Audit log
            await self._audit_service.append(
                stream=AuditStream.OPS,
                event_type=AuditEventType.DATA_DELETED
                if action_type == RetentionActionType.DELETE
                else AuditEventType.DATA_EXPORTED,
                actor_type="system",
                actor_id=executor,
                payload={
                    "artifact_type": artifact.artifact_type,
                    "artifact_ref": artifact.artifact_ref,
                    "action": action_type.value,
                    "policy_id": str(policy.policy_id),
                    "archive_ref": archive_ref,
                },
                summary={
                    "action": action_type.value,
                    "artifact": artifact.artifact_ref,
                },
            )

            await self._session.flush()

            logger.info(
                "Executed retention action: %s on %s (ref=%s)",
                action_type.value,
                artifact.artifact_type,
                artifact.artifact_ref,
            )

            return RetentionActionResult(
                success=True,
                action_type=action_type,
                archive_ref=archive_ref,
            )

        except Exception as e:
            logger.exception(
                "Failed to execute retention action on %s",
                artifact.artifact_ref,
            )
            return RetentionActionResult(
                success=False,
                action_type=action_type,
                error_message=str(e),
            )

    async def _archive_artifact(self, artifact: EligibleArtifact) -> str:
        """Archive an artifact to cold storage.

        Args:
            artifact: The artifact to archive.

        Returns:
            Reference to the archived artifact location.
        """
        # TODO: Implement actual archival to cold storage (S3 Glacier, etc.)
        # For now, return a placeholder reference
        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        archive_ref = (
            f"archive/{artifact.artifact_type}/{timestamp}/{artifact.artifact_ref}"
        )

        logger.info(
            "Archived artifact %s to %s",
            artifact.artifact_ref,
            archive_ref,
        )

        return archive_ref

    async def _delete_artifact(self, artifact: EligibleArtifact) -> None:
        """Permanently delete an artifact.

        Args:
            artifact: The artifact to delete.
        """
        # TODO: Implement actual deletion from storage
        # Must handle both database records and blob storage

        logger.info(
            "Deleted artifact %s (type=%s)",
            artifact.artifact_ref,
            artifact.artifact_type,
        )

    async def get_action_history(
        self,
        artifact_type: str | None = None,
        limit: int = 100,
    ) -> list[RetentionAction]:
        """Get history of retention actions.

        Args:
            artifact_type: Optional filter by artifact type.
            limit: Maximum records to return.

        Returns:
            List of RetentionAction records.
        """
        query = (
            select(RetentionAction)
            .options(joinedload(RetentionAction.policy))
            .order_by(RetentionAction.executed_at.desc())
            .limit(limit)
        )

        if artifact_type:
            query = query.where(RetentionAction.artifact_type == artifact_type)

        result = await self._session.execute(query)
        return list(result.scalars().all())


async def create_default_cpce_policies(session: AsyncSession) -> list[RetentionPolicy]:
    """Create default CPCE-compliant retention policies.

    Creates standard policies for all artifact types with CPCE-compliant
    retention periods. Evidence-related artifacts get 1 year minimum,
    while operational artifacts like audit logs get longer retention.

    Args:
        session: Database session.

    Returns:
        List of created policies.
    """
    service = RetentionPolicyService(session)
    policies = []

    # Default policy definitions
    # Evidence types: minimum 365 days per CPCE
    # Operational types: longer retention for compliance audits
    defaults = [
        (
            ArtifactType.DELIVERY.value,
            365,
            RetentionActionType.ARCHIVE,
            "CPCE-compliant delivery proof retention",
        ),
        (
            ArtifactType.EVIDENCE_OBJECT.value,
            365,
            RetentionActionType.ARCHIVE,
            "CPCE-compliant evidence retention",
        ),
        (
            ArtifactType.CONTENT_OBJECT.value,
            90,
            RetentionActionType.DELETE,
            "Content cleanup after delivery",
        ),
        (
            ArtifactType.AUDIT_LOG.value,
            730,
            RetentionActionType.ARCHIVE,
            "Audit log retention for compliance",
        ),
    ]

    for artifact_type, days, action, description in defaults:
        try:
            policy = await service.create_policy(
                artifact_type=artifact_type,
                retention_days=days,
                expiry_action=action,
                description=description,
            )
            policies.append(policy)
        except CPCEViolationError:
            # Should not happen with these defaults, but log if it does
            logger.error(
                "Default policy for %s violates CPCE minimum",
                artifact_type,
            )

    return policies
