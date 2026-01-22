"""Retention job handler for enforcing data retention policies.

Covers: REQ-F05 (one-year proof retention), REQ-H02 (retention enforcement)

This handler enforces retention policies by:
- Finding artifacts that have exceeded their retention period
- Archiving or deleting them per policy configuration
- Creating audit trail records for compliance

The actual enforcement logic is delegated to RetentionEnforcementService
to avoid code duplication and maintain testability.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import AuditStream, RetentionActionType
from qerds.services.audit_log import AuditEventType, AuditLogService
from qerds.services.retention import (
    RetentionEnforcementService,
    RetentionPolicyService,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)

# CPCE requires minimum 1 year retention for delivery proofs
MINIMUM_PROOF_RETENTION_DAYS = 365


async def enforce_retention_handler(
    session: AsyncSession,
    job: Job,
) -> dict[str, Any] | None:
    """Handle retention_enforce jobs for data lifecycle management.

    This handler:
    1. Loads active retention policies
    2. Finds artifacts eligible for retention action
    3. Archives or deletes per policy
    4. Records actions for audit compliance

    Expected job payload:
        artifact_type: (optional) Specific artifact type to process
        dry_run: (optional) If True, only report what would be done (default: False)
        batch_size: (optional) Maximum artifacts to process (default: 100)

    Args:
        session: Database session for the transaction.
        job: The job being processed.

    Returns:
        Result dict with retention enforcement details.
    """
    payload = job.payload_json or {}

    artifact_type = payload.get("artifact_type")
    dry_run = payload.get("dry_run", False)
    batch_size = payload.get("batch_size", 100)

    # Initialize services
    policy_service = RetentionPolicyService(session)
    enforcement_service = RetentionEnforcementService(session)
    audit_service = AuditLogService(session)

    # Load active retention policies
    policies = await policy_service.get_active_policies(artifact_type=artifact_type)

    if not policies:
        logger.info("No active retention policies found")
        return {
            "processed": 0,
            "archived": 0,
            "deleted": 0,
            "dry_run": dry_run,
        }

    total_processed = 0
    total_archived = 0
    total_deleted = 0
    actions_taken: list[dict[str, Any]] = []

    for policy in policies:
        # Find eligible artifacts for this policy
        remaining_batch = batch_size - total_processed
        if remaining_batch <= 0:
            break

        eligible_artifacts = await enforcement_service.find_eligible_artifacts(
            policy=policy,
            limit=remaining_batch,
        )

        # Process each eligible artifact
        for artifact in eligible_artifacts:
            result = await enforcement_service.execute_action(
                artifact=artifact,
                policy=policy,
                dry_run=dry_run,
                executor="worker:retention",
            )

            total_processed += 1

            if result.success:
                if policy.expiry_action == RetentionActionType.ARCHIVE:
                    total_archived += 1
                elif policy.expiry_action == RetentionActionType.DELETE:
                    total_deleted += 1

            actions_taken.append(
                {
                    "artifact_type": artifact.artifact_type,
                    "artifact_ref": artifact.artifact_ref,
                    "action": policy.expiry_action.value,
                    "success": result.success,
                    "archive_ref": result.archive_ref,
                    "error": result.error_message,
                    "dry_run": dry_run,
                }
            )

            if total_processed >= batch_size:
                break

    # Log enforcement summary to audit trail
    await audit_service.append(
        stream=AuditStream.OPS,
        event_type=AuditEventType.MAINTENANCE_COMPLETED,
        actor_type="system",
        actor_id="worker:retention",
        payload={
            "operation": "retention_enforcement",
            "dry_run": dry_run,
            "policies_evaluated": len(policies),
            "total_processed": total_processed,
            "total_archived": total_archived,
            "total_deleted": total_deleted,
        },
        summary={
            "processed": total_processed,
            "archived": total_archived,
            "deleted": total_deleted,
            "dry_run": dry_run,
        },
    )

    logger.info(
        "Retention enforcement complete: processed=%d, archived=%d, deleted=%d, dry_run=%s",
        total_processed,
        total_archived,
        total_deleted,
        dry_run,
    )

    return {
        "processed": total_processed,
        "archived": total_archived,
        "deleted": total_deleted,
        "dry_run": dry_run,
        "policies_evaluated": len(policies),
        "actions": actions_taken[:10],  # Limit response size
    }
