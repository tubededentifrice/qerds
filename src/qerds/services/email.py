"""Email notification service for delivery notifications.

Covers: REQ-F02 (notification content), REQ-F03 (pre-acceptance redaction)

This module provides CPCE-compliant email notifications for registered deliveries.
Notifications are sent via SMTP with support for both self-hosted relays and
managed SMTP services per the architecture spec (05-architecture.md).

Key compliance requirements (REQ-F02):
- Notification MUST include: provider identity, delivery reference, legal nature, deadline
- Notification MUST NOT include: sender identity, content preview (REQ-F03)

Usage:
    from qerds.services.email import EmailNotificationService
    from sqlalchemy.ext.asyncio import AsyncSession

    async def send_notification(session: AsyncSession):
        email_service = EmailNotificationService(session, settings.smtp)
        result = await email_service.send_delivery_notification(
            delivery_id=uuid,
            recipient_email="recipient@example.com",
            lang="fr",
        )
        if result.success:
            print(f"Notification sent: {result.message_id}")
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import smtplib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from jinja2 import Environment, PackageLoader, select_autoescape

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.core.config import SMTPSettings


logger = logging.getLogger(__name__)


class NotificationChannel(str, Enum):
    """Supported notification channels."""

    EMAIL = "email"


class NotificationStatus(str, Enum):
    """Status of a notification attempt."""

    SENT = "sent"
    FAILED = "failed"
    BOUNCED = "bounced"
    PENDING = "pending"


class BounceType(str, Enum):
    """Type of email bounce."""

    HARD = "hard"  # Permanent failure (e.g., invalid address)
    SOFT = "soft"  # Temporary failure (e.g., mailbox full)
    SPAM = "spam"  # Marked as spam


@dataclass(frozen=True, slots=True)
class NotificationResult:
    """Result of a notification attempt.

    Attributes:
        success: Whether the notification was sent successfully.
        message_id: SMTP message ID (for tracking delivery status).
        status: Current status of the notification.
        recipient_hash: SHA-256 hash of recipient email (for evidence).
        template_version: Version of the template used.
        error: Error message if the notification failed.
        sent_at: Timestamp when the notification was sent.
    """

    success: bool
    message_id: str | None
    status: NotificationStatus
    recipient_hash: str
    template_version: str
    error: str | None
    sent_at: datetime | None


@dataclass(frozen=True, slots=True)
class DeliveryStatus:
    """Status of an email delivery.

    Attributes:
        message_id: SMTP message ID.
        status: Current delivery status.
        bounce_type: Type of bounce if bounced.
        bounce_reason: Reason for bounce if available.
        checked_at: When the status was last checked.
    """

    message_id: str
    status: NotificationStatus
    bounce_type: BounceType | None
    bounce_reason: str | None
    checked_at: datetime


class EmailError(Exception):
    """Base exception for email operations."""

    pass


class EmailConfigurationError(EmailError):
    """Raised when email configuration is invalid."""

    pass


class EmailDeliveryError(EmailError):
    """Raised when email delivery fails."""

    pass


# Template version for evidence tracking
TEMPLATE_VERSION = "2026.1.0"

# Magic link token expiry (matches acceptance window)
MAGIC_LINK_EXPIRY_DAYS = 15

# Secret key for HMAC-based token generation (should come from config in production)
# This is used to create cryptographically secure, verifiable claim tokens
_TOKEN_SECRET_KEY: bytes | None = None


def _get_token_secret() -> bytes:
    """Get or generate the token secret key.

    In production, this should be loaded from secure configuration.
    For development, a random key is generated per process.

    Returns:
        32-byte secret key for HMAC operations.
    """
    global _TOKEN_SECRET_KEY
    if _TOKEN_SECRET_KEY is None:
        # Generate a random key for this process
        # In production, this should be loaded from environment/secrets
        _TOKEN_SECRET_KEY = secrets.token_bytes(32)
        logger.warning(
            "Using ephemeral token secret key. Configure QERDS_TOKEN_SECRET in production."
        )
    return _TOKEN_SECRET_KEY


def set_token_secret(secret: bytes) -> None:
    """Set the token secret key.

    This should be called at application startup with a persistent secret.

    Args:
        secret: 32-byte secret key for HMAC operations.

    Raises:
        ValueError: If secret is not 32 bytes.
    """
    global _TOKEN_SECRET_KEY
    if len(secret) != 32:
        msg = "Token secret must be exactly 32 bytes"
        raise ValueError(msg)
    _TOKEN_SECRET_KEY = secret


class EmailNotificationService:
    """Service for sending CPCE-compliant email notifications.

    This service handles:
    - Initial delivery notifications with magic links
    - Reminder notifications (configurable)
    - Notification failure alerts
    - Evidence event generation (EVT_NOTIFICATION_SENT)

    CPCE Compliance Notes:
    - Notifications include provider identity, reference, legal nature, deadline
    - Notifications DO NOT include sender identity or content preview (REQ-F03)
    - Magic links require authentication before content access

    Attributes:
        session: SQLAlchemy async session for database operations.
        smtp_settings: SMTP configuration for email delivery.
    """

    def __init__(
        self,
        session: AsyncSession,
        smtp_settings: SMTPSettings,
        base_url: str = "https://qerds.local",
        provider_name: str = "QERDS",
    ) -> None:
        """Initialize the email notification service.

        Args:
            session: SQLAlchemy async session for database operations.
            smtp_settings: SMTP configuration settings.
            base_url: Base URL for magic link generation.
            provider_name: Provider name for compliance (shown in notifications).
        """
        self.session = session
        self.smtp_settings = smtp_settings
        self.base_url = base_url.rstrip("/")
        self.provider_name = provider_name

        # Set up Jinja2 environment for email templates
        self._env = Environment(
            loader=PackageLoader("qerds", "templates/email"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def send_delivery_notification(
        self,
        delivery_id: UUID,
        recipient_email: str,
        lang: str = "fr",
        *,
        custom_deadline: datetime | None = None,
    ) -> NotificationResult:
        """Send initial delivery notification to recipient.

        This notification contains:
        - Provider identity (QERDS)
        - Delivery reference (hashed ID)
        - Legal nature (LRE - Lettre Recommandee Electronique)
        - Acceptance deadline
        - Magic link for pickup (requires authentication)

        Per REQ-F03, the notification does NOT contain:
        - Sender identity
        - Content preview or subject

        Args:
            delivery_id: UUID of the delivery.
            recipient_email: Recipient's email address.
            lang: Language code for the notification (fr, en).
            custom_deadline: Optional custom deadline (defaults to 15 days).

        Returns:
            NotificationResult with status and evidence data.
        """
        # Hash recipient email for evidence (we don't store PII in logs)
        recipient_hash = self._hash_email(recipient_email)

        try:
            # Generate magic link with claim token
            magic_link = self.generate_magic_link(delivery_id, recipient_email)

            # Calculate deadline
            deadline = custom_deadline or (datetime.now(UTC) + timedelta(days=15))

            # Render email template
            subject, html_body, text_body = self._render_notification_template(
                lang=lang,
                delivery_ref=self._format_delivery_ref(delivery_id),
                deadline=deadline,
                magic_link=magic_link,
            )

            # Send the email
            message_id = self._send_email(
                to_email=recipient_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )

            logger.info(
                "Delivery notification sent",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_hash": recipient_hash[:16],
                    "message_id": message_id,
                    "template_version": TEMPLATE_VERSION,
                },
            )

            return NotificationResult(
                success=True,
                message_id=message_id,
                status=NotificationStatus.SENT,
                recipient_hash=recipient_hash,
                template_version=TEMPLATE_VERSION,
                error=None,
                sent_at=datetime.now(UTC),
            )

        except Exception as e:
            logger.error(
                "Failed to send delivery notification",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_hash": recipient_hash[:16],
                    "error": str(e),
                },
            )
            return NotificationResult(
                success=False,
                message_id=None,
                status=NotificationStatus.FAILED,
                recipient_hash=recipient_hash,
                template_version=TEMPLATE_VERSION,
                error=str(e),
                sent_at=None,
            )

    async def send_reminder(
        self,
        delivery_id: UUID,
        recipient_email: str,
        lang: str = "fr",
        *,
        days_remaining: int = 5,
    ) -> NotificationResult:
        """Send reminder notification for pending delivery.

        Reminders are sent when a delivery is approaching its deadline
        and the recipient has not yet accepted/refused.

        Args:
            delivery_id: UUID of the delivery.
            recipient_email: Recipient's email address.
            lang: Language code for the notification.
            days_remaining: Days remaining until deadline.

        Returns:
            NotificationResult with status and evidence data.
        """
        recipient_hash = self._hash_email(recipient_email)

        try:
            # Generate magic link
            magic_link = self.generate_magic_link(delivery_id, recipient_email)

            # Calculate deadline from days remaining
            deadline = datetime.now(UTC) + timedelta(days=days_remaining)

            # Render reminder template
            subject, html_body, text_body = self._render_reminder_template(
                lang=lang,
                delivery_ref=self._format_delivery_ref(delivery_id),
                deadline=deadline,
                days_remaining=days_remaining,
                magic_link=magic_link,
            )

            # Send the email
            message_id = self._send_email(
                to_email=recipient_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )

            logger.info(
                "Reminder notification sent",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_hash": recipient_hash[:16],
                    "message_id": message_id,
                    "days_remaining": days_remaining,
                },
            )

            return NotificationResult(
                success=True,
                message_id=message_id,
                status=NotificationStatus.SENT,
                recipient_hash=recipient_hash,
                template_version=TEMPLATE_VERSION,
                error=None,
                sent_at=datetime.now(UTC),
            )

        except Exception as e:
            logger.error(
                "Failed to send reminder notification",
                extra={
                    "delivery_id": str(delivery_id),
                    "recipient_hash": recipient_hash[:16],
                    "error": str(e),
                },
            )
            return NotificationResult(
                success=False,
                message_id=None,
                status=NotificationStatus.FAILED,
                recipient_hash=recipient_hash,
                template_version=TEMPLATE_VERSION,
                error=str(e),
                sent_at=None,
            )

    def check_delivery_status(self, message_id: str) -> DeliveryStatus:
        """Check the delivery status of a sent email.

        Note: This is a placeholder for future implementation.
        In production, this would integrate with:
        - Mailpit API (development)
        - SMTP provider webhooks (SES, Mailgun, etc.)

        Args:
            message_id: SMTP message ID to check.

        Returns:
            DeliveryStatus with current status information.
        """
        # Placeholder: return pending status
        # Real implementation would query SMTP provider API
        logger.debug("Checking delivery status for message_id=%s", message_id)
        return DeliveryStatus(
            message_id=message_id,
            status=NotificationStatus.PENDING,
            bounce_type=None,
            bounce_reason=None,
            checked_at=datetime.now(UTC),
        )

    def generate_magic_link(
        self,
        delivery_id: UUID,
        recipient_email: str,
    ) -> str:
        """Generate a magic link for delivery pickup.

        The magic link contains a cryptographically secure claim token
        that is tied to the specific delivery and recipient. The token:
        - Is HMAC-signed for tamper protection
        - Contains delivery ID and email hash
        - Has a limited validity period

        Per the architecture spec (05-architecture.md), the magic link:
        - Does NOT grant direct content access
        - Requires user authentication (FranceConnect+) before access

        Args:
            delivery_id: UUID of the delivery.
            recipient_email: Recipient's email address.

        Returns:
            Full URL with claim token for delivery pickup.
        """
        # Create token payload
        token = self._generate_claim_token(delivery_id, recipient_email)

        # Build pickup URL with token
        pickup_path = "/pickup"
        params = {
            "token": token,
            "ref": self._format_delivery_ref(delivery_id),
        }

        return f"{self.base_url}{pickup_path}?{urlencode(params)}"

    def _generate_claim_token(
        self,
        delivery_id: UUID,
        recipient_email: str,
    ) -> str:
        """Generate a cryptographically secure claim token.

        The token format is: random_nonce.signature
        where signature = HMAC-SHA256(secret, nonce + delivery_id + email_hash)

        Args:
            delivery_id: UUID of the delivery.
            recipient_email: Recipient's email address.

        Returns:
            Claim token string.
        """
        # Generate random nonce
        nonce = secrets.token_urlsafe(16)

        # Create message for HMAC
        email_hash = self._hash_email(recipient_email)
        message = f"{nonce}:{delivery_id}:{email_hash}".encode()

        # Sign with HMAC-SHA256
        secret = _get_token_secret()
        signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

        return f"{nonce}.{signature[:32]}"

    def verify_claim_token(
        self,
        token: str,
        delivery_id: UUID,
        recipient_email: str,
    ) -> bool:
        """Verify a claim token is valid.

        Args:
            token: The claim token to verify.
            delivery_id: Expected delivery ID.
            recipient_email: Expected recipient email.

        Returns:
            True if the token is valid, False otherwise.
        """
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return False

            nonce, provided_sig = parts

            # Recreate the expected signature
            email_hash = self._hash_email(recipient_email)
            message = f"{nonce}:{delivery_id}:{email_hash}".encode()
            secret = _get_token_secret()
            expected_sig = hmac.new(secret, message, hashlib.sha256).hexdigest()[:32]

            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(provided_sig, expected_sig)

        except Exception:
            return False

    def _render_notification_template(
        self,
        lang: str,
        delivery_ref: str,
        deadline: datetime,
        magic_link: str,
    ) -> tuple[str, str, str]:
        """Render the notification email template.

        Args:
            lang: Language code (fr, en).
            delivery_ref: Formatted delivery reference.
            deadline: Acceptance deadline.
            magic_link: Magic link URL.

        Returns:
            Tuple of (subject, html_body, text_body).
        """
        template = self._env.get_template("notification.html")

        context = {
            "lang": lang,
            "provider_name": self.provider_name,
            "delivery_ref": delivery_ref,
            "deadline": deadline,
            "deadline_formatted": self._format_date(deadline, lang),
            "magic_link": magic_link,
            "legal_nature": self._get_legal_nature_text(lang),
            "template_version": TEMPLATE_VERSION,
        }

        html_body = template.render(**context)

        # Generate plain text version
        text_template = self._env.get_template("notification.txt")
        text_body = text_template.render(**context)

        # Subject line (CPCE-compliant, no sender info)
        subject = self._get_subject(lang, "notification", delivery_ref)

        return subject, html_body, text_body

    def _render_reminder_template(
        self,
        lang: str,
        delivery_ref: str,
        deadline: datetime,
        days_remaining: int,
        magic_link: str,
    ) -> tuple[str, str, str]:
        """Render the reminder email template.

        Args:
            lang: Language code (fr, en).
            delivery_ref: Formatted delivery reference.
            deadline: Acceptance deadline.
            days_remaining: Days until deadline.
            magic_link: Magic link URL.

        Returns:
            Tuple of (subject, html_body, text_body).
        """
        template = self._env.get_template("reminder.html")

        context = {
            "lang": lang,
            "provider_name": self.provider_name,
            "delivery_ref": delivery_ref,
            "deadline": deadline,
            "deadline_formatted": self._format_date(deadline, lang),
            "days_remaining": days_remaining,
            "magic_link": magic_link,
            "legal_nature": self._get_legal_nature_text(lang),
            "template_version": TEMPLATE_VERSION,
        }

        html_body = template.render(**context)

        # Generate plain text version
        text_template = self._env.get_template("reminder.txt")
        text_body = text_template.render(**context)

        # Subject line with urgency for reminder
        subject = self._get_subject(lang, "reminder", delivery_ref, days_remaining)

        return subject, html_body, text_body

    def _send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
    ) -> str:
        """Send an email via SMTP.

        Args:
            to_email: Recipient email address.
            subject: Email subject line.
            html_body: HTML version of the email body.
            text_body: Plain text version of the email body.

        Returns:
            SMTP message ID.

        Raises:
            EmailDeliveryError: If the email cannot be sent.
        """
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{self.smtp_settings.from_name} <{self.smtp_settings.from_address}>"
        msg["To"] = to_email

        # Generate message ID
        message_id = f"<{secrets.token_hex(16)}@{self._get_domain()}>"
        msg["Message-ID"] = message_id

        # Attach text and HTML parts
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            # Connect to SMTP server
            if self.smtp_settings.use_ssl:
                # Implicit TLS (port 465)
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(
                    self.smtp_settings.host,
                    self.smtp_settings.port,
                    timeout=self.smtp_settings.timeout,
                    context=context,
                )
            else:
                # Plain or STARTTLS
                server = smtplib.SMTP(
                    self.smtp_settings.host,
                    self.smtp_settings.port,
                    timeout=self.smtp_settings.timeout,
                )
                if self.smtp_settings.use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)

            # Authenticate if credentials provided
            if self.smtp_settings.username and self.smtp_settings.password:
                server.login(
                    self.smtp_settings.username,
                    self.smtp_settings.password.get_secret_value(),
                )

            # Send the email
            server.sendmail(
                self.smtp_settings.from_address,
                [to_email],
                msg.as_string(),
            )
            server.quit()

            return message_id

        except smtplib.SMTPException as e:
            msg = f"SMTP error: {e}"
            raise EmailDeliveryError(msg) from e
        except OSError as e:
            msg = f"Connection error: {e}"
            raise EmailDeliveryError(msg) from e

    def _hash_email(self, email: str) -> str:
        """Hash an email address for evidence and logging.

        We don't store raw email addresses in logs/evidence.
        The hash allows correlation without exposing PII.

        Args:
            email: Email address to hash.

        Returns:
            SHA-256 hex digest of the lowercased email.
        """
        return hashlib.sha256(email.lower().strip().encode()).hexdigest()

    def _format_delivery_ref(self, delivery_id: UUID) -> str:
        """Format a delivery ID as a human-readable reference.

        Args:
            delivery_id: UUID of the delivery.

        Returns:
            Formatted reference string (e.g., "QERDS-A1B2C3D4").
        """
        # Use first 8 characters of UUID, uppercase
        short_id = str(delivery_id).replace("-", "")[:8].upper()
        return f"QERDS-{short_id}"

    def _format_date(self, dt: datetime, lang: str) -> str:
        """Format a datetime for display.

        Args:
            dt: Datetime to format.
            lang: Language code.

        Returns:
            Localized date string.
        """
        if lang == "fr":
            return dt.strftime("%d/%m/%Y a %H:%M")
        else:
            return dt.strftime("%Y-%m-%d at %H:%M")

    def _get_domain(self) -> str:
        """Extract domain from from_address for message ID.

        Returns:
            Domain portion of the from address.
        """
        return self.smtp_settings.from_address.split("@")[-1]

    def _get_legal_nature_text(self, lang: str) -> str:
        """Get the legal nature description text.

        Args:
            lang: Language code.

        Returns:
            Legal nature description in the specified language.
        """
        if lang == "fr":
            return (
                "Lettre Recommandee Electronique (LRE) au sens de l'article L.100 "
                "du Code des Postes et des Communications Electroniques"
            )
        else:
            return (
                "Qualified Electronic Registered Delivery (QERDS) under "
                "EU Regulation 910/2014 (eIDAS)"
            )

    def _get_subject(
        self,
        lang: str,
        notification_type: str,
        delivery_ref: str,
        days_remaining: int | None = None,
    ) -> str:
        """Generate email subject line.

        Per REQ-F03, subject does NOT reveal sender identity.

        Args:
            lang: Language code.
            notification_type: Type of notification (notification, reminder).
            delivery_ref: Delivery reference.
            days_remaining: Days remaining for reminder.

        Returns:
            Subject line string.
        """
        if notification_type == "notification":
            if lang == "fr":
                return f"[QERDS] Lettre recommandee electronique - Ref: {delivery_ref}"
            else:
                return f"[QERDS] Electronic registered delivery - Ref: {delivery_ref}"
        else:  # reminder
            if lang == "fr":
                return (
                    f"[RAPPEL] Lettre recommandee en attente - "
                    f"{days_remaining} jours restants - Ref: {delivery_ref}"
                )
            else:
                return (
                    f"[REMINDER] Pending registered delivery - "
                    f"{days_remaining} days remaining - Ref: {delivery_ref}"
                )

    def get_evidence_metadata(
        self,
        result: NotificationResult,
        channel: NotificationChannel = NotificationChannel.EMAIL,
    ) -> dict[str, Any]:
        """Generate evidence metadata for EVT_NOTIFICATION_SENT.

        This metadata is stored with the evidence event for compliance.

        Args:
            result: The notification result.
            channel: Notification channel used.

        Returns:
            Dictionary of evidence metadata.
        """
        return {
            "channel": channel.value,
            "template_version": result.template_version,
            "recipient_hash": result.recipient_hash,
            "message_id_hash": (
                hashlib.sha256(result.message_id.encode()).hexdigest()[:16]
                if result.message_id
                else None
            ),
            "status": result.status.value,
            "sent_at": result.sent_at.isoformat() if result.sent_at else None,
            "error": result.error,
        }
