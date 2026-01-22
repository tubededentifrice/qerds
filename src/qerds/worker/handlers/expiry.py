"""Expiry job handler for checking delivery acceptance window expiry.

Covers: REQ-F04 (15-day acceptance window)

This handler processes delivery_expire jobs to:
- Find deliveries that have exceeded their acceptance deadline
- Transition them to EXPIRED state
- Create evidence events for compliance
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from qerds.db.models.base import AuditStream, DeliveryState, EventType
from qerds.db.models.deliveries import Delivery
from qerds.db.models.evidence import EvidenceEvent
from qerds.services.audit_log import AuditEventType, AuditLogService
from qerds.services.job_queue import JobQueueService, JobType

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)

# States that can transition to EXPIRED
EXPIRABLE_STATES = (
    DeliveryState.NOTIFIED,
    DeliveryState.AVAILABLE,
)


async def check_expiry_handler(
    session: AsyncSession,
    job: Job,
) -> dict[str, Any] | None:
    """Handle delivery_expire jobs.

    This handler can operate in two modes:
    1. Single delivery mode: Check and expire a specific delivery
    2. Batch mode: Find and expire all expired deliveries

    Expected job payload:
        delivery_id: (optional) UUID of specific delivery to check
        batch_size: (optional) Maximum deliveries to process in batch mode (default: 100)

    Args:
        session: Database session for the transaction.
        job: The job being processed.

    Returns:
        Result dict with expiry details.
    """
    payload = job.payload_json or {}
    delivery_id = payload.get("delivery_id")
    batch_size = payload.get("batch_size", 100)

    now = datetime.now(UTC)
    expired_count = 0
    expired_ids = []

    if delivery_id:
        # Single delivery mode
        result = await _check_single_delivery(session, delivery_id, now)
        if result["expired"]:
            expired_count = 1
            expired_ids = [delivery_id]
    else:
        # Batch mode: find and expire all expired deliveries
        expired_deliveries = await _find_expired_deliveries(session, now, batch_size)

        for delivery in expired_deliveries:
            try:
                await _expire_delivery(session, delivery, now)
                expired_count += 1
                expired_ids.append(str(delivery.delivery_id))
            except Exception as e:
                logger.exception(
                    "Failed to expire delivery: delivery_id=%s, error=%s",
                    delivery.delivery_id,
                    e,
                )
                # Continue processing other deliveries

        # If there are more deliveries to process, schedule another batch job
        if len(expired_deliveries) >= batch_size:
            job_queue = JobQueueService(session)
            await job_queue.enqueue(
                job_type=JobType.DELIVERY_EXPIRE,
                payload={"batch_size": batch_size},
                priority=50,  # Lower priority than user-triggered jobs
            )
            logger.info("Scheduled continuation job for remaining expired deliveries")

    logger.info(
        "Expiry check complete: expired=%d, delivery_ids=%s",
        expired_count,
        expired_ids[:10],  # Log first 10 for brevity
    )

    return {
        "expired_count": expired_count,
        "expired_ids": expired_ids,
        "checked_at": now.isoformat(),
    }


async def _check_single_delivery(
    session: AsyncSession,
    delivery_id: str,
    now: datetime,
) -> dict[str, Any]:
    """Check and potentially expire a single delivery.

    Args:
        session: Database session.
        delivery_id: UUID string of the delivery to check.
        now: Current timestamp.

    Returns:
        Dict with expiry status and details.
    """
    import uuid

    stmt = select(Delivery).where(Delivery.delivery_id == uuid.UUID(delivery_id))
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if delivery is None:
        logger.warning("Delivery not found for expiry check: %s", delivery_id)
        return {"expired": False, "reason": "not_found"}

    if delivery.state not in EXPIRABLE_STATES:
        return {"expired": False, "reason": f"state={delivery.state.value}"}

    if delivery.acceptance_deadline_at is None:
        return {"expired": False, "reason": "no_deadline"}

    if delivery.acceptance_deadline_at > now:
        return {"expired": False, "reason": "not_yet_expired"}

    # Delivery has expired
    await _expire_delivery(session, delivery, now)
    return {"expired": True, "delivery_id": delivery_id}


async def _find_expired_deliveries(
    session: AsyncSession,
    now: datetime,
    limit: int,
) -> list[Delivery]:
    """Find deliveries that have exceeded their acceptance deadline.

    Args:
        session: Database session.
        now: Current timestamp.
        limit: Maximum number of deliveries to return.

    Returns:
        List of expired Delivery objects.
    """
    stmt = (
        select(Delivery)
        .where(
            Delivery.state.in_([s.value for s in EXPIRABLE_STATES]),
            Delivery.acceptance_deadline_at.isnot(None),
            Delivery.acceptance_deadline_at <= now,
        )
        .order_by(Delivery.acceptance_deadline_at)
        .limit(limit)
    )

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _expire_delivery(
    session: AsyncSession,
    delivery: Delivery,
    now: datetime,
) -> None:
    """Transition a delivery to EXPIRED state.

    Creates evidence event and audit log entry for compliance.

    Args:
        session: Database session.
        delivery: The delivery to expire.
        now: Current timestamp.
    """
    old_state = delivery.state.value

    # Update delivery state
    delivery.state = DeliveryState.EXPIRED
    delivery.completed_at = now

    # Create evidence event
    event = EvidenceEvent(
        delivery_id=delivery.delivery_id,
        event_type=EventType.EVT_EXPIRED,
        event_time=now,
        actor_type="system",
        actor_ref="worker:expiry",
        event_metadata={
            "previous_state": old_state,
            "deadline": (
                delivery.acceptance_deadline_at.isoformat()
                if delivery.acceptance_deadline_at
                else None
            ),
            "expired_at": now.isoformat(),
        },
    )
    session.add(event)

    # Log to audit trail
    audit_service = AuditLogService(session)
    deadline_iso = (
        delivery.acceptance_deadline_at.isoformat() if delivery.acceptance_deadline_at else None
    )
    await audit_service.append(
        stream=AuditStream.EVIDENCE,
        event_type=AuditEventType.DELIVERY_EXPIRED,
        actor_type="system",
        actor_id="worker:expiry",
        resource_type="delivery",
        resource_id=str(delivery.delivery_id),
        payload={
            "previous_state": old_state,
            "deadline": deadline_iso,
            "expired_at": now.isoformat(),
        },
        summary={
            "previous_state": old_state,
        },
    )

    logger.info(
        "Delivery expired: delivery_id=%s, previous_state=%s, deadline=%s",
        delivery.delivery_id,
        old_state,
        delivery.acceptance_deadline_at,
    )
