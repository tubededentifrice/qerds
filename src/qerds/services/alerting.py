"""Security event alerting service for incident detection (REQ-H04, REQ-D08).

This module provides configurable alerting for security-relevant events:
- Authentication failures (with threshold-based detection)
- Permission denials on sensitive resources
- Audit chain integrity failures
- Configuration changes
- Administrative session events

Alerting supports multiple channels:
- Webhook: JSON payload POST to configurable endpoint
- Email: Template-based notifications via SMTP

The service integrates with the security event logging system to provide
real-time incident detection and response support as required by ETSI
EN 319 401/319 521 obligations.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from qerds.core.config import SMTPSettings
    from qerds.services.security_events import SecurityEventPayload

logger = logging.getLogger(__name__)


class AlertEventType(str, Enum):
    """Types of events that can trigger alerts.

    These event types map to security-relevant conditions that require
    incident detection and response per REQ-H04.
    """

    # Authentication anomalies
    AUTH_FAILURE_THRESHOLD = "auth_failure_threshold"
    AUTH_BRUTE_FORCE = "auth_brute_force"

    # Authorization violations
    PERMISSION_DENIED = "permission_denied"
    SENSITIVE_RESOURCE_ACCESS = "sensitive_resource_access"

    # Integrity events
    AUDIT_CHAIN_BROKEN = "audit_chain_broken"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"

    # Administrative events
    CONFIG_CHANGED = "config_changed"
    ADMIN_SESSION_CREATED = "admin_session_created"
    KEY_OPERATION = "key_operation"

    # System events
    SYSTEM_ERROR = "system_error"


class AlertSeverity(str, Enum):
    """Severity levels for alerts.

    Used to prioritize incident response and filter alert destinations.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(str, Enum):
    """Supported alert delivery channels."""

    WEBHOOK = "webhook"
    EMAIL = "email"


@dataclass(frozen=True, slots=True)
class AlertPayload:
    """Structured payload for an alert.

    Contains all information needed for incident detection and triage.

    Attributes:
        alert_id: Unique identifier for this alert instance.
        event_type: Type of event that triggered the alert.
        severity: Alert severity level.
        title: Brief human-readable title.
        description: Detailed description of the alert condition.
        actor_id: Identifier of the actor involved (if applicable).
        resource_type: Type of resource affected.
        resource_id: Identifier of the affected resource.
        details: Additional context-specific details.
        timestamp: When the alert was generated.
        source_events: References to source security events.
    """

    alert_id: str
    event_type: AlertEventType
    severity: AlertSeverity
    title: str
    description: str
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_events: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert payload to dictionary for serialization."""
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "actor_id": self.actor_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "source_events": self.source_events,
        }


@dataclass
class AlertingConfig:
    """Configuration for the alerting service.

    Attributes:
        enabled: Master switch for alerting.
        webhook_url: URL for webhook alert delivery.
        webhook_secret: Shared secret for webhook HMAC signature.
        email_recipients: List of email addresses for email alerts.
        enabled_events: Set of event types that trigger alerts.
        auth_failure_threshold: Number of failures before alerting.
        auth_failure_window_seconds: Time window for failure counting.
        severity_filter: Minimum severity to alert on per channel.
        rate_limit_per_minute: Maximum alerts per minute per event type.
    """

    enabled: bool = True
    webhook_url: str | None = None
    webhook_secret: str | None = None
    email_recipients: list[str] = field(default_factory=list)
    enabled_events: set[AlertEventType] = field(
        default_factory=lambda: {
            AlertEventType.AUTH_FAILURE_THRESHOLD,
            AlertEventType.PERMISSION_DENIED,
            AlertEventType.AUDIT_CHAIN_BROKEN,
            AlertEventType.CONFIG_CHANGED,
            AlertEventType.ADMIN_SESSION_CREATED,
        }
    )
    auth_failure_threshold: int = 5
    auth_failure_window_seconds: int = 300  # 5 minutes
    severity_filter: dict[AlertChannel, AlertSeverity] = field(
        default_factory=lambda: {
            AlertChannel.WEBHOOK: AlertSeverity.LOW,
            AlertChannel.EMAIL: AlertSeverity.HIGH,
        }
    )
    rate_limit_per_minute: int = 10

    def is_event_enabled(self, event_type: AlertEventType) -> bool:
        """Check if an event type is enabled for alerting."""
        return self.enabled and event_type in self.enabled_events


@dataclass
class AlertResult:
    """Result of an alert delivery attempt.

    Attributes:
        success: Whether the alert was delivered successfully.
        channel: Delivery channel used.
        alert_id: ID of the alert.
        error: Error message if delivery failed.
        delivered_at: Timestamp of successful delivery.
    """

    success: bool
    channel: AlertChannel
    alert_id: str
    error: str | None = None
    delivered_at: datetime | None = None


class AlertingError(Exception):
    """Base exception for alerting operations."""

    pass


class WebhookDeliveryError(AlertingError):
    """Raised when webhook delivery fails."""

    pass


class EmailDeliveryError(AlertingError):
    """Raised when email delivery fails."""

    pass


class AlertingService:
    """Service for security event alerting.

    This service monitors security events and triggers alerts when
    configurable thresholds or conditions are met. It supports:
    - Threshold-based detection (e.g., N auth failures in M minutes)
    - Immediate alerts for critical events
    - Multiple delivery channels (webhook, email)
    - Rate limiting to prevent alert fatigue

    The service is designed to support incident detection and response
    workflows as required by REQ-H04.

    Example:
        config = AlertingConfig(
            webhook_url="https://alerts.example.com/webhook",
            enabled_events={AlertEventType.AUTH_FAILURE_THRESHOLD},
        )
        service = AlertingService(config)

        # Process a security event
        await service.process_security_event(security_payload)
    """

    def __init__(
        self,
        config: AlertingConfig,
        smtp_settings: SMTPSettings | None = None,
    ) -> None:
        """Initialize the alerting service.

        Args:
            config: Alerting configuration.
            smtp_settings: SMTP settings for email alerts (optional).
        """
        self._config = config
        self._smtp_settings = smtp_settings

        # Track auth failures per actor for threshold detection
        # Key: actor_id, Value: list of (timestamp, event_id)
        self._auth_failures: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

        # Rate limiting: track alerts sent per event type
        # Key: (event_type, minute_bucket), Value: count
        self._rate_limit_counters: dict[tuple[AlertEventType, int], int] = defaultdict(int)

        # HTTP client for webhook delivery
        self._http_client: httpx.AsyncClient | None = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client for webhook delivery."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def process_security_event(
        self,
        event: SecurityEventPayload,
    ) -> list[AlertResult]:
        """Process a security event and trigger alerts if conditions are met.

        This method analyzes the incoming security event and determines
        if it should trigger one or more alerts based on the configuration.

        Args:
            event: The security event payload to process.

        Returns:
            List of alert results (one per delivery channel used).
        """
        if not self._config.enabled:
            return []

        alerts_to_send: list[AlertPayload] = []

        # Map security event types to alert conditions
        event_type_str = event.event_type.value

        # Check for auth failure threshold
        if event_type_str == "auth_failure":
            alert = await self._check_auth_failure_threshold(event)
            if alert:
                alerts_to_send.append(alert)

        # Check for permission denied on sensitive resources
        if event_type_str == "authz_denied":
            alert = self._check_permission_denied(event)
            if alert:
                alerts_to_send.append(alert)

        # Check for config changes
        if event_type_str == "config_changed":
            alert = self._check_config_change(event)
            if alert:
                alerts_to_send.append(alert)

        # Check for admin session creation
        if event_type_str == "auth_success" and event.actor.actor_type == "admin":
            alert = self._check_admin_session(event)
            if alert:
                alerts_to_send.append(alert)

        # Check for key operations
        if event_type_str.startswith("key_"):
            alert = self._check_key_operation(event)
            if alert:
                alerts_to_send.append(alert)

        # Send all triggered alerts
        results: list[AlertResult] = []
        for alert in alerts_to_send:
            delivery_results = await self._send_alert(alert)
            results.extend(delivery_results)

        return results

    async def send_integrity_alert(
        self,
        *,
        alert_type: AlertEventType,
        title: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> list[AlertResult]:
        """Send an alert for integrity-related issues.

        Used for audit chain breaks, evidence verification failures, etc.

        Args:
            alert_type: Type of integrity alert.
            title: Alert title.
            description: Detailed description.
            details: Additional context.

        Returns:
            List of alert delivery results.
        """
        if not self._config.is_event_enabled(alert_type):
            return []

        alert = AlertPayload(
            alert_id=self._generate_alert_id(),
            event_type=alert_type,
            severity=AlertSeverity.CRITICAL,
            title=title,
            description=description,
            details=details or {},
        )

        return await self._send_alert(alert)

    async def _check_auth_failure_threshold(
        self,
        event: SecurityEventPayload,
    ) -> AlertPayload | None:
        """Check if auth failures exceed threshold for an actor.

        Implements threshold-based detection: triggers an alert when
        an actor exceeds N authentication failures within M seconds.
        """
        if not self._config.is_event_enabled(AlertEventType.AUTH_FAILURE_THRESHOLD):
            return None

        actor_id = event.actor.actor_id
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=self._config.auth_failure_window_seconds)

        # Add this failure to the tracking list
        event_id = event.details.get("event_id", str(id(event)))
        self._auth_failures[actor_id].append((now, event_id))

        # Remove old entries outside the window
        self._auth_failures[actor_id] = [
            (ts, eid) for ts, eid in self._auth_failures[actor_id] if ts >= window_start
        ]

        failures = self._auth_failures[actor_id]
        failure_count = len(failures)

        # Check if threshold exceeded
        if failure_count >= self._config.auth_failure_threshold:
            # Clear the failures to avoid repeated alerts
            event_ids = [eid for _, eid in failures]
            self._auth_failures[actor_id] = []

            return AlertPayload(
                alert_id=self._generate_alert_id(),
                event_type=AlertEventType.AUTH_FAILURE_THRESHOLD,
                severity=AlertSeverity.HIGH,
                title=f"Authentication failure threshold exceeded for {actor_id}",
                description=(
                    f"Actor {actor_id} has failed authentication {failure_count} times "
                    f"within {self._config.auth_failure_window_seconds} seconds. "
                    "This may indicate a brute-force attack."
                ),
                actor_id=actor_id,
                details={
                    "failure_count": failure_count,
                    "window_seconds": self._config.auth_failure_window_seconds,
                    "threshold": self._config.auth_failure_threshold,
                    "ip_address": event.actor.ip_address,
                },
                source_events=event_ids,
            )

        return None

    def _check_permission_denied(
        self,
        event: SecurityEventPayload,
    ) -> AlertPayload | None:
        """Check for permission denied on sensitive resources."""
        if not self._config.is_event_enabled(AlertEventType.PERMISSION_DENIED):
            return None

        # Alert on denied access to sensitive resource types
        sensitive_resources = {"evidence", "audit_log", "key", "config", "user"}
        if event.resource_type not in sensitive_resources:
            return None

        return AlertPayload(
            alert_id=self._generate_alert_id(),
            event_type=AlertEventType.PERMISSION_DENIED,
            severity=AlertSeverity.MEDIUM,
            title=f"Permission denied for {event.actor.actor_id} on {event.resource_type}",
            description=(
                f"Actor {event.actor.actor_id} was denied access to "
                f"{event.resource_type}/{event.resource_id}. "
                f"Action: {event.action}"
            ),
            actor_id=event.actor.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            details={
                "action": event.action,
                "ip_address": event.actor.ip_address,
                "permission": event.details.get("permission"),
            },
        )

    def _check_config_change(
        self,
        event: SecurityEventPayload,
    ) -> AlertPayload | None:
        """Check for configuration changes that require alerting."""
        if not self._config.is_event_enabled(AlertEventType.CONFIG_CHANGED):
            return None

        return AlertPayload(
            alert_id=self._generate_alert_id(),
            event_type=AlertEventType.CONFIG_CHANGED,
            severity=AlertSeverity.MEDIUM,
            title=f"Configuration changed: {event.resource_id}",
            description=(
                f"Configuration key {event.resource_id} was changed by {event.actor.actor_id}."
            ),
            actor_id=event.actor.actor_id,
            resource_type="config",
            resource_id=event.resource_id,
            details={
                "config_key": event.details.get("config_key"),
                # Values are intentionally omitted for security
                "changed_at": event.timestamp.isoformat(),
            },
        )

    def _check_admin_session(
        self,
        event: SecurityEventPayload,
    ) -> AlertPayload | None:
        """Check for admin session creation events."""
        if not self._config.is_event_enabled(AlertEventType.ADMIN_SESSION_CREATED):
            return None

        return AlertPayload(
            alert_id=self._generate_alert_id(),
            event_type=AlertEventType.ADMIN_SESSION_CREATED,
            severity=AlertSeverity.LOW,
            title=f"Admin session created for {event.actor.actor_id}",
            description=(
                f"Administrative user {event.actor.actor_id} started a new session "
                f"from {event.actor.ip_address or 'unknown IP'}."
            ),
            actor_id=event.actor.actor_id,
            resource_type="session",
            details={
                "ip_address": event.actor.ip_address,
                "user_agent": event.actor.user_agent,
                "session_id": event.actor.session_id,
            },
        )

    def _check_key_operation(
        self,
        event: SecurityEventPayload,
    ) -> AlertPayload | None:
        """Check for key operations that require alerting."""
        if not self._config.is_event_enabled(AlertEventType.KEY_OPERATION):
            return None

        operation = event.details.get("operation", event.action)

        return AlertPayload(
            alert_id=self._generate_alert_id(),
            event_type=AlertEventType.KEY_OPERATION,
            severity=AlertSeverity.HIGH,
            title=f"Key operation: {operation}",
            description=(
                f"Key operation '{operation}' performed by {event.actor.actor_id} "
                f"on key {event.resource_id or 'new key'}."
            ),
            actor_id=event.actor.actor_id,
            resource_type="key",
            resource_id=event.resource_id,
            details={
                "operation": operation,
                "key_type": event.details.get("key_type"),
            },
        )

    async def _send_alert(self, alert: AlertPayload) -> list[AlertResult]:
        """Send an alert through configured channels.

        Respects rate limiting and severity filtering.
        """
        results: list[AlertResult] = []

        # Check rate limit
        if not self._check_rate_limit(alert.event_type):
            logger.warning(
                "Alert rate limit exceeded for event_type=%s",
                alert.event_type.value,
            )
            return results

        # Send to webhook if configured
        if self._config.webhook_url:
            min_severity = self._config.severity_filter.get(AlertChannel.WEBHOOK, AlertSeverity.LOW)
            if self._severity_gte(alert.severity, min_severity):
                result = await self._send_webhook(alert)
                results.append(result)

        # Send email if configured
        if self._config.email_recipients and self._smtp_settings:
            min_severity = self._config.severity_filter.get(AlertChannel.EMAIL, AlertSeverity.HIGH)
            if self._severity_gte(alert.severity, min_severity):
                result = await self._send_email(alert)
                results.append(result)

        return results

    async def _send_webhook(self, alert: AlertPayload) -> AlertResult:
        """Send alert to webhook endpoint."""
        if not self._config.webhook_url:
            return AlertResult(
                success=False,
                channel=AlertChannel.WEBHOOK,
                alert_id=alert.alert_id,
                error="Webhook URL not configured",
            )

        try:
            client = await self._get_http_client()
            payload = json.dumps(alert.to_dict(), default=str)

            headers = {
                "Content-Type": "application/json",
                "X-Alert-ID": alert.alert_id,
                "X-Alert-Severity": alert.severity.value,
            }

            # Add HMAC signature if secret is configured
            if self._config.webhook_secret:
                signature = self._compute_webhook_signature(payload, self._config.webhook_secret)
                headers["X-Signature-SHA256"] = signature

            response = await client.post(
                self._config.webhook_url,
                content=payload,
                headers=headers,
            )

            if response.status_code >= 200 and response.status_code < 300:
                logger.info(
                    "Webhook alert delivered: alert_id=%s, status=%d",
                    alert.alert_id,
                    response.status_code,
                )
                return AlertResult(
                    success=True,
                    channel=AlertChannel.WEBHOOK,
                    alert_id=alert.alert_id,
                    delivered_at=datetime.now(UTC),
                )
            else:
                error = f"Webhook returned status {response.status_code}"
                logger.error(
                    "Webhook alert failed: alert_id=%s, error=%s",
                    alert.alert_id,
                    error,
                )
                return AlertResult(
                    success=False,
                    channel=AlertChannel.WEBHOOK,
                    alert_id=alert.alert_id,
                    error=error,
                )

        except httpx.RequestError as e:
            error = f"Webhook request failed: {e}"
            logger.error(
                "Webhook alert failed: alert_id=%s, error=%s",
                alert.alert_id,
                error,
            )
            return AlertResult(
                success=False,
                channel=AlertChannel.WEBHOOK,
                alert_id=alert.alert_id,
                error=error,
            )

    async def _send_email(self, alert: AlertPayload) -> AlertResult:
        """Send alert via email.

        Uses async wrapper around smtplib for non-blocking I/O.
        """
        if not self._smtp_settings or not self._config.email_recipients:
            return AlertResult(
                success=False,
                channel=AlertChannel.EMAIL,
                alert_id=alert.alert_id,
                error="Email not configured",
            )

        try:
            # Run synchronous SMTP in thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._send_email_sync,
                alert,
            )

            logger.info(
                "Email alert delivered: alert_id=%s, recipients=%d",
                alert.alert_id,
                len(self._config.email_recipients),
            )
            return AlertResult(
                success=True,
                channel=AlertChannel.EMAIL,
                alert_id=alert.alert_id,
                delivered_at=datetime.now(UTC),
            )

        except Exception as e:
            error = f"Email delivery failed: {e}"
            logger.error(
                "Email alert failed: alert_id=%s, error=%s",
                alert.alert_id,
                error,
            )
            return AlertResult(
                success=False,
                channel=AlertChannel.EMAIL,
                alert_id=alert.alert_id,
                error=error,
            )

    def _send_email_sync(self, alert: AlertPayload) -> None:
        """Synchronous email sending for thread pool execution."""
        import smtplib
        import ssl
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        if not self._smtp_settings:
            raise EmailDeliveryError("SMTP settings not configured")

        # Build email message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"
        msg["From"] = f"{self._smtp_settings.from_name} <{self._smtp_settings.from_address}>"
        msg["To"] = ", ".join(self._config.email_recipients)

        # Plain text body
        text_body = self._render_email_text(alert)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))

        # HTML body
        html_body = self._render_email_html(alert)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        # Send via SMTP
        if self._smtp_settings.use_ssl:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(
                self._smtp_settings.host,
                self._smtp_settings.port,
                timeout=self._smtp_settings.timeout,
                context=context,
            )
        else:
            server = smtplib.SMTP(
                self._smtp_settings.host,
                self._smtp_settings.port,
                timeout=self._smtp_settings.timeout,
            )
            if self._smtp_settings.use_tls:
                context = ssl.create_default_context()
                server.starttls(context=context)

        try:
            if self._smtp_settings.username and self._smtp_settings.password:
                server.login(
                    self._smtp_settings.username,
                    self._smtp_settings.password.get_secret_value(),
                )

            server.sendmail(
                self._smtp_settings.from_address,
                self._config.email_recipients,
                msg.as_string(),
            )
        finally:
            server.quit()

    def _render_email_text(self, alert: AlertPayload) -> str:
        """Render plain text email body."""
        lines = [
            f"Security Alert: {alert.title}",
            "=" * 60,
            "",
            f"Severity: {alert.severity.value.upper()}",
            f"Event Type: {alert.event_type.value}",
            f"Time: {alert.timestamp.isoformat()}",
            f"Alert ID: {alert.alert_id}",
            "",
            "Description:",
            alert.description,
            "",
        ]

        if alert.actor_id:
            lines.append(f"Actor: {alert.actor_id}")
        if alert.resource_type:
            lines.append(f"Resource: {alert.resource_type}/{alert.resource_id}")

        if alert.details:
            lines.append("")
            lines.append("Details:")
            for key, value in alert.details.items():
                if value is not None:
                    lines.append(f"  {key}: {value}")

        lines.append("")
        lines.append("---")
        lines.append("This is an automated security alert from QERDS.")

        return "\n".join(lines)

    def _render_email_html(self, alert: AlertPayload) -> str:
        """Render HTML email body."""
        severity_colors = {
            AlertSeverity.LOW: "#28a745",
            AlertSeverity.MEDIUM: "#ffc107",
            AlertSeverity.HIGH: "#fd7e14",
            AlertSeverity.CRITICAL: "#dc3545",
        }
        color = severity_colors.get(alert.severity, "#6c757d")

        details_html = ""
        if alert.details:
            items = "".join(
                f"<li><strong>{k}:</strong> {v}</li>"
                for k, v in alert.details.items()
                if v is not None
            )
            details_html = f"<h3>Details</h3><ul>{items}</ul>"

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .alert-box {{ border-left: 4px solid {color}; padding: 16px; background: #f8f9fa; }}
        .severity {{ color: {color}; font-weight: bold; }}
        .meta {{ color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="alert-box">
        <h2>{alert.title}</h2>
        <p class="severity">{alert.severity.value.upper()}</p>
        <p>{alert.description}</p>
    </div>
    <p class="meta">
        Event Type: {alert.event_type.value}<br>
        Time: {alert.timestamp.isoformat()}<br>
        Alert ID: {alert.alert_id}
        {f"<br>Actor: {alert.actor_id}" if alert.actor_id else ""}
        {f"<br>Resource: {alert.resource_type}/{alert.resource_id}" if alert.resource_type else ""}
    </p>
    {details_html}
    <hr>
    <p class="meta">This is an automated security alert from QERDS.</p>
</body>
</html>
"""

    def _generate_alert_id(self) -> str:
        """Generate a unique alert ID."""
        import secrets

        timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
        random_suffix = secrets.token_hex(4)
        return f"alert-{timestamp}-{random_suffix}"

    def _compute_webhook_signature(self, payload: str, secret: str) -> str:
        """Compute HMAC-SHA256 signature for webhook payload."""
        import hmac

        signature = hmac.new(
            secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={signature}"

    def _check_rate_limit(self, event_type: AlertEventType) -> bool:
        """Check if an alert should be rate-limited.

        Returns True if the alert can be sent, False if rate-limited.
        """
        now = datetime.now(UTC)
        minute_bucket = int(now.timestamp() // 60)
        key = (event_type, minute_bucket)

        # Clean old buckets (keep only current and previous minute)
        keys_to_remove = [k for k in self._rate_limit_counters if k[1] < minute_bucket - 1]
        for k in keys_to_remove:
            del self._rate_limit_counters[k]

        current_count = self._rate_limit_counters[key]
        if current_count >= self._config.rate_limit_per_minute:
            return False

        self._rate_limit_counters[key] = current_count + 1
        return True

    def _severity_gte(self, severity: AlertSeverity, minimum: AlertSeverity) -> bool:
        """Check if severity is greater than or equal to minimum."""
        order = [
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]
        return order.index(severity) >= order.index(minimum)

    def clear_auth_failure_tracking(self, actor_id: str) -> None:
        """Clear auth failure tracking for an actor.

        Should be called after successful authentication to reset the
        failure counter.

        Args:
            actor_id: The actor whose failures should be cleared.
        """
        if actor_id in self._auth_failures:
            del self._auth_failures[actor_id]


def create_alerting_config_from_env() -> AlertingConfig:
    """Create AlertingConfig from environment variables.

    Environment variables:
        QERDS_ALERTING__ENABLED: Enable/disable alerting
        QERDS_ALERTING__WEBHOOK_URL: Webhook endpoint URL
        QERDS_ALERTING__WEBHOOK_SECRET: Webhook HMAC secret
        QERDS_ALERTING__EMAIL_RECIPIENTS: Comma-separated email addresses
        QERDS_ALERTING__AUTH_FAILURE_THRESHOLD: Number of failures before alert
        QERDS_ALERTING__AUTH_FAILURE_WINDOW: Window in seconds

    Returns:
        AlertingConfig populated from environment.
    """
    import os

    enabled = os.environ.get("QERDS_ALERTING__ENABLED", "true").lower() == "true"
    webhook_url = os.environ.get("QERDS_ALERTING__WEBHOOK_URL")
    webhook_secret = os.environ.get("QERDS_ALERTING__WEBHOOK_SECRET")

    email_recipients_str = os.environ.get("QERDS_ALERTING__EMAIL_RECIPIENTS", "")
    email_recipients = [e.strip() for e in email_recipients_str.split(",") if e.strip()]

    auth_failure_threshold = int(os.environ.get("QERDS_ALERTING__AUTH_FAILURE_THRESHOLD", "5"))
    auth_failure_window = int(os.environ.get("QERDS_ALERTING__AUTH_FAILURE_WINDOW", "300"))

    return AlertingConfig(
        enabled=enabled,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
        email_recipients=email_recipients,
        auth_failure_threshold=auth_failure_threshold,
        auth_failure_window_seconds=auth_failure_window,
    )
