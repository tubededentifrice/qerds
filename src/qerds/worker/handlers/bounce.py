"""Bounce job handler for processing email bounce notifications.

Covers: REQ-F02 (notification tracking)

This handler processes bounce notifications from the email system to:
- Update delivery state when notifications fail permanently
- Track bounce reasons for compliance
- Trigger alternative notification channels if available
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
from qerds.services.email import BounceType

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)


async def process_bounce_handler(
    session: AsyncSession,
    job: Job,
) -> dict[str, Any] | None:
    """Handle process_bounce jobs for email delivery failures.

    This handler processes bounce notifications from the email system
    (e.g., webhook callbacks from SMTP provider). It:
    1. Records the bounce in the evidence trail
    2. Updates delivery state if appropriate
    3. Logs the bounce for compliance

    Expected job payload:
        delivery_id: UUID of the associated delivery
        message_id: SMTP message ID that bounced
        bounce_type: Type of bounce (hard, soft, spam)
        bounce_reason: Reason string from the email system
        bounced_at: ISO timestamp of the bounce (optional)
        recipient_email_hash: SHA-256 hash of the recipient email

    Args:
        session: Database session for the transaction.
        job: The job being processed.

    Returns:
        Result dict with bounce processing details.

    Raises:
        ValueError: If required payload fields are missing.
    """
    payload = job.payload_json or {}

    # Validate required fields
    delivery_id = payload.get("delivery_id")
    if not delivery_id:
        msg = "delivery_id is required in job payload"
        raise ValueError(msg)

    message_id = payload.get("message_id")
    bounce_type_str = payload.get("bounce_type", "soft")
    bounce_reason = payload.get("bounce_reason", "Unknown bounce reason")
    bounced_at_str = payload.get("bounced_at")
    recipient_email_hash = payload.get("recipient_email_hash")

    # Parse bounce type
    try:
        bounce_type = BounceType(bounce_type_str)
    except ValueError:
        bounce_type = BounceType.SOFT
        logger.warning("Unknown bounce type '%s', treating as soft", bounce_type_str)

    # Parse bounce timestamp
    bounced_at = datetime.fromisoformat(bounced_at_str) if bounced_at_str else datetime.now(UTC)

    # Retrieve the delivery
    delivery = await _get_delivery(session, delivery_id)
    if delivery is None:
        logger.warning("Delivery not found for bounce: delivery_id=%s", delivery_id)
        return {
            "processed": False,
            "reason": "delivery_not_found",
            "delivery_id": delivery_id,
        }

    # Create evidence event for the bounce
    event_metadata = {
        "message_id": message_id,
        "bounce_type": bounce_type.value,
        "bounce_reason": bounce_reason,
        "bounced_at": bounced_at.isoformat(),
        "recipient_email_hash": recipient_email_hash,
    }

    event = EvidenceEvent(
        delivery_id=delivery.delivery_id,
        event_type=EventType.EVT_NOTIFICATION_FAILED,
        event_time=bounced_at,
        actor_type="system",
        actor_ref="email_bounce",
        event_metadata=event_metadata,
    )
    session.add(event)

    # Determine if we need to update delivery state
    state_changed = False
    if bounce_type == BounceType.HARD:
        # Hard bounces (permanent failures) may require state change
        if delivery.state in (DeliveryState.DEPOSITED, DeliveryState.NOTIFIED):
            delivery.state = DeliveryState.NOTIFICATION_FAILED
            state_changed = True
            logger.warning(
                "Delivery state changed to NOTIFICATION_FAILED due to hard bounce: "
                "delivery_id=%s, bounce_reason=%s",
                delivery_id,
                bounce_reason,
            )
    elif bounce_type == BounceType.SPAM and delivery.state in (
        DeliveryState.DEPOSITED,
        DeliveryState.NOTIFIED,
    ):
        # Spam complaints are serious - treat like hard bounce
        delivery.state = DeliveryState.NOTIFICATION_FAILED
        state_changed = True
        logger.warning(
            "Delivery state changed to NOTIFICATION_FAILED due to spam complaint: delivery_id=%s",
            delivery_id,
        )
    # Soft bounces don't change state - the notification job will retry

    # Log to audit trail
    audit_service = AuditLogService(session)
    await audit_service.append(
        stream=AuditStream.EVIDENCE,
        event_type=AuditEventType.DELIVERY_NOTIFIED,  # Using NOTIFIED for bounce tracking
        actor_type="system",
        actor_id="email_bounce",
        resource_type="delivery",
        resource_id=str(delivery.delivery_id),
        payload={
            "message_id": message_id,
            "bounce_type": bounce_type.value,
            "bounce_reason": bounce_reason,
            "state_changed": state_changed,
            "new_state": delivery.state.value if state_changed else None,
        },
        summary={
            "bounce_type": bounce_type.value,
            "state_changed": state_changed,
        },
    )

    logger.info(
        "Bounce processed: delivery_id=%s, bounce_type=%s, message_id=%s, state_changed=%s",
        delivery_id,
        bounce_type.value,
        message_id,
        state_changed,
    )

    return {
        "processed": True,
        "delivery_id": delivery_id,
        "bounce_type": bounce_type.value,
        "bounce_reason": bounce_reason,
        "state_changed": state_changed,
        "new_state": delivery.state.value if state_changed else None,
    }


async def _get_delivery(session: AsyncSession, delivery_id: str) -> Delivery | None:
    """Retrieve a delivery by ID.

    Args:
        session: Database session.
        delivery_id: UUID string of the delivery.

    Returns:
        The Delivery object or None if not found.
    """
    import uuid

    stmt = select(Delivery).where(Delivery.delivery_id == uuid.UUID(delivery_id))
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
