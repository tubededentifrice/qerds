"""Notification job handler for sending email notifications.

Covers: REQ-F02 (notification content), REQ-F03 (pre-acceptance redaction)

This handler processes notification_send jobs to deliver:
- Initial delivery notifications to recipients
- Reminder notifications for pending deliveries

The handler uses EmailNotificationService for CPCE-compliant email delivery.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from qerds.db.models.base import AuditStream, DeliveryState, EventType
from qerds.db.models.deliveries import Delivery
from qerds.db.models.evidence import EvidenceEvent
from qerds.db.models.parties import Party
from qerds.services.audit_log import AuditEventType, AuditLogService
from qerds.services.email import EmailNotificationService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.core.config import SMTPSettings
    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)


async def send_notification_handler(
    session: AsyncSession,
    job: Job,
) -> dict[str, Any] | None:
    """Handle notification_send jobs.

    This handler:
    1. Retrieves the delivery and recipient information
    2. Sends the appropriate notification type (initial or reminder)
    3. Creates an evidence event for the notification
    4. Updates the audit log

    Expected job payload:
        delivery_id: UUID of the delivery to notify about
        notification_type: "initial" or "reminder" (default: "initial")
        lang: Language code for the notification (default: "fr")
        days_remaining: Days until deadline (for reminders)

    Args:
        session: Database session for the transaction.
        job: The job being processed.

    Returns:
        Result dict with notification details.

    Raises:
        ValueError: If required payload fields are missing.
        LookupError: If the delivery or recipient cannot be found.
    """
    payload = job.payload_json or {}

    # Validate required fields
    delivery_id = payload.get("delivery_id")
    if not delivery_id:
        msg = "delivery_id is required in job payload"
        raise ValueError(msg)

    notification_type = payload.get("notification_type", "initial")
    lang = payload.get("lang", "fr")
    days_remaining = payload.get("days_remaining", 5)

    # Retrieve the delivery
    delivery = await _get_delivery(session, delivery_id)
    if delivery is None:
        msg = f"Delivery not found: {delivery_id}"
        raise LookupError(msg)

    # Verify delivery is in a state that allows notification
    if notification_type == "initial" and delivery.state not in (
        DeliveryState.DEPOSITED,
        DeliveryState.NOTIFIED,
    ):
        logger.warning(
            "Skipping notification for delivery in state %s: delivery_id=%s",
            delivery.state.value,
            delivery_id,
        )
        return {"skipped": True, "reason": f"delivery_state={delivery.state.value}"}

    # Get recipient party and email
    recipient = await _get_party(session, delivery.recipient_party_id)
    if recipient is None:
        msg = f"Recipient party not found: {delivery.recipient_party_id}"
        raise LookupError(msg)

    recipient_email = recipient.email
    if not recipient_email:
        msg = f"Recipient has no email address: {delivery.recipient_party_id}"
        raise ValueError(msg)

    # Create email service with SMTP settings from environment
    smtp_settings = _get_smtp_settings()
    email_service = EmailNotificationService(
        session=session,
        smtp_settings=smtp_settings,
        base_url=os.environ.get("BASE_URL", "https://qerds.local"),
        provider_name=os.environ.get("PROVIDER_NAME", "QERDS"),
    )

    # Send the appropriate notification type
    if notification_type == "reminder":
        result = await email_service.send_reminder(
            delivery_id=delivery.delivery_id,
            recipient_email=recipient_email,
            lang=lang,
            days_remaining=days_remaining,
        )
    else:
        result = await email_service.send_delivery_notification(
            delivery_id=delivery.delivery_id,
            recipient_email=recipient_email,
            lang=lang,
            custom_deadline=delivery.acceptance_deadline_at,
        )

    # Determine the event type based on notification result
    if result.success:
        event_type = EventType.EVT_NOTIFICATION_SENT
    else:
        event_type = EventType.EVT_NOTIFICATION_FAILED

    # Create evidence event for compliance tracking
    await _create_evidence_event(
        session=session,
        delivery=delivery,
        event_type=event_type,
        metadata=email_service.get_evidence_metadata(result),
    )

    # Update delivery state if this was the initial notification
    if (
        notification_type == "initial"
        and result.success
        and delivery.state == DeliveryState.DEPOSITED
    ):
        delivery.state = DeliveryState.NOTIFIED
        delivery.notified_at = result.sent_at

    # Log to audit trail
    audit_service = AuditLogService(session)
    await audit_service.append(
        stream=AuditStream.EVIDENCE,
        event_type=AuditEventType.DELIVERY_NOTIFIED,
        actor_type="system",
        actor_id="worker",
        resource_type="delivery",
        resource_id=str(delivery.delivery_id),
        payload={
            "notification_type": notification_type,
            "recipient_hash": result.recipient_hash,
            "message_id": result.message_id,
            "success": result.success,
            "error": result.error,
        },
        summary={
            "notification_type": notification_type,
            "success": result.success,
        },
    )

    logger.info(
        "Notification %s: delivery_id=%s, type=%s, message_id=%s",
        "sent" if result.success else "failed",
        delivery_id,
        notification_type,
        result.message_id,
    )

    return {
        "success": result.success,
        "notification_type": notification_type,
        "message_id": result.message_id,
        "recipient_hash": result.recipient_hash,
        "error": result.error,
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


async def _get_party(session: AsyncSession, party_id: Any) -> Party | None:
    """Retrieve a party by ID.

    Args:
        session: Database session.
        party_id: UUID of the party.

    Returns:
        The Party object or None if not found.
    """
    stmt = select(Party).where(Party.party_id == party_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def _create_evidence_event(
    session: AsyncSession,
    delivery: Delivery,
    event_type: EventType,
    metadata: dict[str, Any],
) -> None:
    """Create an evidence event for notification tracking.

    Args:
        session: Database session.
        delivery: The delivery being notified about.
        event_type: Type of evidence event.
        metadata: Notification metadata for evidence.
    """
    from datetime import UTC, datetime

    event = EvidenceEvent(
        delivery_id=delivery.delivery_id,
        event_type=event_type,
        event_time=datetime.now(UTC),
        actor_type="system",
        actor_ref="worker",
        event_metadata=metadata,
    )
    session.add(event)


def _get_smtp_settings() -> SMTPSettings:
    """Build SMTP settings from environment variables.

    Returns:
        SMTPSettings instance configured from environment.
    """
    from pydantic import SecretStr

    from qerds.core.config import SMTPSettings

    # Build password with proper handling of empty strings
    smtp_password = os.environ.get("SMTP_PASSWORD")
    password_secret = SecretStr(smtp_password) if smtp_password else None

    return SMTPSettings(
        host=os.environ.get("SMTP_HOST", "localhost"),
        port=int(os.environ.get("SMTP_PORT", "1025")),
        username=os.environ.get("SMTP_USERNAME"),
        password=password_secret,
        use_tls=os.environ.get("SMTP_USE_TLS", "false").lower() == "true",
        use_ssl=os.environ.get("SMTP_USE_SSL", "false").lower() == "true",
        from_address=os.environ.get("SMTP_FROM_ADDRESS", "noreply@qerds.local"),
        from_name=os.environ.get("SMTP_FROM_NAME", "QERDS"),
    )
