"""Tests for security event alerting service.

Tests cover:
- AlertingConfig validation and behavior
- AlertPayload construction and serialization
- AlertingService event processing
- Threshold-based auth failure detection
- Webhook delivery with HMAC signatures
- Email delivery
- Rate limiting
- Severity filtering
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qerds.services.alerting import (
    AlertChannel,
    AlertEventType,
    AlertingConfig,
    AlertingService,
    AlertPayload,
    AlertResult,
    AlertSeverity,
    create_alerting_config_from_env,
)
from qerds.services.security_events import (
    SecurityActor,
    SecurityEventPayload,
    SecurityEventType,
)


class TestAlertEventType:
    """Tests for AlertEventType enumeration."""

    def test_all_event_types_have_values(self):
        """All alert event types have string values."""
        event_types = [
            AlertEventType.AUTH_FAILURE_THRESHOLD,
            AlertEventType.AUTH_BRUTE_FORCE,
            AlertEventType.PERMISSION_DENIED,
            AlertEventType.SENSITIVE_RESOURCE_ACCESS,
            AlertEventType.AUDIT_CHAIN_BROKEN,
            AlertEventType.EVIDENCE_INTEGRITY_FAILURE,
            AlertEventType.CONFIG_CHANGED,
            AlertEventType.ADMIN_SESSION_CREATED,
            AlertEventType.KEY_OPERATION,
            AlertEventType.SYSTEM_ERROR,
        ]
        assert all(e.value for e in event_types)


class TestAlertSeverity:
    """Tests for AlertSeverity enumeration."""

    def test_all_severities_have_values(self):
        """All severity levels have string values."""
        severities = [
            AlertSeverity.LOW,
            AlertSeverity.MEDIUM,
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]
        assert all(s.value for s in severities)


class TestAlertPayload:
    """Tests for AlertPayload dataclass."""

    def test_minimal_payload(self):
        """Payload can be created with required fields only."""
        payload = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.AUTH_FAILURE_THRESHOLD,
            severity=AlertSeverity.HIGH,
            title="Test Alert",
            description="Test description",
        )
        assert payload.alert_id == "alert-123"
        assert payload.event_type == AlertEventType.AUTH_FAILURE_THRESHOLD
        assert payload.severity == AlertSeverity.HIGH
        assert payload.actor_id is None
        assert payload.resource_type is None

    def test_full_payload(self):
        """Payload can be created with all fields."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        payload = AlertPayload(
            alert_id="alert-456",
            event_type=AlertEventType.PERMISSION_DENIED,
            severity=AlertSeverity.MEDIUM,
            title="Access Denied",
            description="Permission was denied",
            actor_id="user-123",
            resource_type="evidence",
            resource_id="ev-789",
            details={"permission": "read"},
            timestamp=timestamp,
            source_events=["event-1", "event-2"],
        )
        assert payload.actor_id == "user-123"
        assert payload.resource_type == "evidence"
        assert payload.details == {"permission": "read"}
        assert payload.source_events == ["event-1", "event-2"]

    def test_payload_to_dict(self):
        """Payload serializes to dictionary correctly."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        payload = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.CONFIG_CHANGED,
            severity=AlertSeverity.MEDIUM,
            title="Config Changed",
            description="A configuration was modified",
            actor_id="admin-1",
            timestamp=timestamp,
        )

        result = payload.to_dict()

        assert result["alert_id"] == "alert-123"
        assert result["event_type"] == "config_changed"
        assert result["severity"] == "medium"
        assert result["title"] == "Config Changed"
        assert result["timestamp"] == "2024-01-15T10:30:00+00:00"


class TestAlertingConfig:
    """Tests for AlertingConfig dataclass."""

    def test_default_config(self):
        """Default config has expected values."""
        config = AlertingConfig()

        assert config.enabled is True
        assert config.webhook_url is None
        assert config.auth_failure_threshold == 5
        assert config.auth_failure_window_seconds == 300
        assert config.rate_limit_per_minute == 10

    def test_default_enabled_events(self):
        """Default config enables expected event types."""
        config = AlertingConfig()

        assert AlertEventType.AUTH_FAILURE_THRESHOLD in config.enabled_events
        assert AlertEventType.PERMISSION_DENIED in config.enabled_events
        assert AlertEventType.AUDIT_CHAIN_BROKEN in config.enabled_events
        assert AlertEventType.CONFIG_CHANGED in config.enabled_events
        assert AlertEventType.ADMIN_SESSION_CREATED in config.enabled_events

    def test_is_event_enabled(self):
        """is_event_enabled checks both master switch and event set."""
        config = AlertingConfig(
            enabled=True,
            enabled_events={AlertEventType.AUTH_FAILURE_THRESHOLD},
        )

        assert config.is_event_enabled(AlertEventType.AUTH_FAILURE_THRESHOLD) is True
        assert config.is_event_enabled(AlertEventType.PERMISSION_DENIED) is False

    def test_is_event_enabled_when_disabled(self):
        """is_event_enabled returns False when alerting is disabled."""
        config = AlertingConfig(
            enabled=False,
            enabled_events={AlertEventType.AUTH_FAILURE_THRESHOLD},
        )

        assert config.is_event_enabled(AlertEventType.AUTH_FAILURE_THRESHOLD) is False

    def test_custom_severity_filter(self):
        """Custom severity filters can be configured."""
        config = AlertingConfig(
            severity_filter={
                AlertChannel.WEBHOOK: AlertSeverity.HIGH,
                AlertChannel.EMAIL: AlertSeverity.CRITICAL,
            }
        )

        assert config.severity_filter[AlertChannel.WEBHOOK] == AlertSeverity.HIGH
        assert config.severity_filter[AlertChannel.EMAIL] == AlertSeverity.CRITICAL


class TestAlertResult:
    """Tests for AlertResult dataclass."""

    def test_success_result(self):
        """Successful result has expected fields."""
        result = AlertResult(
            success=True,
            channel=AlertChannel.WEBHOOK,
            alert_id="alert-123",
            delivered_at=datetime.now(UTC),
        )

        assert result.success is True
        assert result.channel == AlertChannel.WEBHOOK
        assert result.error is None

    def test_failure_result(self):
        """Failed result includes error message."""
        result = AlertResult(
            success=False,
            channel=AlertChannel.EMAIL,
            alert_id="alert-123",
            error="SMTP connection failed",
        )

        assert result.success is False
        assert result.error == "SMTP connection failed"


class TestAlertingServiceInit:
    """Tests for AlertingService initialization."""

    def test_init_with_config(self):
        """Service initializes with config."""
        config = AlertingConfig(webhook_url="https://example.com/webhook")
        service = AlertingService(config)

        assert service._config == config
        assert service._smtp_settings is None

    def test_init_with_smtp(self):
        """Service initializes with SMTP settings."""
        config = AlertingConfig()
        smtp = MagicMock()
        service = AlertingService(config, smtp_settings=smtp)

        assert service._smtp_settings == smtp


class TestAlertingServiceProcessEvent:
    """Tests for AlertingService.process_security_event method."""

    @pytest.mark.asyncio
    async def test_disabled_service_returns_empty(self):
        """Disabled service returns empty result list."""
        config = AlertingConfig(enabled=False)
        service = AlertingService(config)

        event = create_mock_security_event(SecurityEventType.AUTH_FAILURE)
        results = await service.process_security_event(event)

        assert results == []

    @pytest.mark.asyncio
    async def test_unhandled_event_type_returns_empty(self):
        """Event types without handlers return empty results."""
        config = AlertingConfig(
            enabled=True,
            enabled_events=set(),  # No events enabled
        )
        service = AlertingService(config)

        event = create_mock_security_event(SecurityEventType.AUTH_SUCCESS)
        results = await service.process_security_event(event)

        assert results == []


class TestAuthFailureThreshold:
    """Tests for authentication failure threshold detection."""

    @pytest.mark.asyncio
    async def test_below_threshold_no_alert(self):
        """Auth failures below threshold don't trigger alerts."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            auth_failure_threshold=5,
        )
        service = AlertingService(config)

        # Mock webhook to track calls
        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            # Send 4 failures (below threshold of 5)
            for _ in range(4):
                event = create_mock_security_event(
                    SecurityEventType.AUTH_FAILURE,
                    actor_id="user-123",
                )
                await service.process_security_event(event)

            # No alerts should be sent
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_threshold_reached_triggers_alert(self):
        """Auth failures at threshold trigger an alert."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            auth_failure_threshold=3,
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            # Send 3 failures (at threshold)
            for _ in range(3):
                event = create_mock_security_event(
                    SecurityEventType.AUTH_FAILURE,
                    actor_id="user-123",
                )
                await service.process_security_event(event)

            # Alert should be sent on the 3rd failure
            assert mock_send.call_count == 1

            # Verify the alert payload
            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.AUTH_FAILURE_THRESHOLD
            assert call_args.severity == AlertSeverity.HIGH
            assert call_args.actor_id == "user-123"
            assert call_args.details["failure_count"] == 3

    @pytest.mark.asyncio
    async def test_different_actors_tracked_separately(self):
        """Auth failures are tracked per actor."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            auth_failure_threshold=2,
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            # User A fails once
            event_a1 = create_mock_security_event(
                SecurityEventType.AUTH_FAILURE,
                actor_id="user-a",
            )
            await service.process_security_event(event_a1)

            # User B fails once
            event_b1 = create_mock_security_event(
                SecurityEventType.AUTH_FAILURE,
                actor_id="user-b",
            )
            await service.process_security_event(event_b1)

            # No alerts yet
            mock_send.assert_not_called()

            # User A fails again (reaches threshold)
            event_a2 = create_mock_security_event(
                SecurityEventType.AUTH_FAILURE,
                actor_id="user-a",
            )
            await service.process_security_event(event_a2)

            # Alert for user-a
            assert mock_send.call_count == 1
            call_args = mock_send.call_args[0][0]
            assert call_args.actor_id == "user-a"

    @pytest.mark.asyncio
    async def test_clear_auth_failure_tracking(self):
        """Successful auth clears failure tracking."""
        config = AlertingConfig(auth_failure_threshold=3)
        service = AlertingService(config)

        # Add some failures
        for _ in range(2):
            event = create_mock_security_event(
                SecurityEventType.AUTH_FAILURE,
                actor_id="user-123",
            )
            await service.process_security_event(event)

        # Clear tracking (simulates successful login)
        service.clear_auth_failure_tracking("user-123")

        # Verify tracking is cleared
        assert "user-123" not in service._auth_failures


class TestPermissionDeniedAlerts:
    """Tests for permission denied alerting."""

    @pytest.mark.asyncio
    async def test_denied_on_sensitive_resource_alerts(self):
        """Permission denied on sensitive resources triggers alert."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.PERMISSION_DENIED},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            event = create_mock_security_event(
                SecurityEventType.AUTHZ_DENIED,
                resource_type="evidence",
                resource_id="ev-123",
            )
            await service.process_security_event(event)

            assert mock_send.call_count == 1
            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.PERMISSION_DENIED
            assert call_args.resource_type == "evidence"

    @pytest.mark.asyncio
    async def test_denied_on_non_sensitive_resource_no_alert(self):
        """Permission denied on non-sensitive resources doesn't alert."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.PERMISSION_DENIED},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            event = create_mock_security_event(
                SecurityEventType.AUTHZ_DENIED,
                resource_type="delivery",  # Not in sensitive list
                resource_id="del-123",
            )
            await service.process_security_event(event)

            mock_send.assert_not_called()


class TestConfigChangeAlerts:
    """Tests for configuration change alerting."""

    @pytest.mark.asyncio
    async def test_config_change_triggers_alert(self):
        """Configuration changes trigger alerts."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.CONFIG_CHANGED},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            event = create_mock_security_event(
                SecurityEventType.CONFIG_CHANGED,
                resource_type="config",
                resource_id="retention_days",
            )
            await service.process_security_event(event)

            assert mock_send.call_count == 1
            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.CONFIG_CHANGED


class TestAdminSessionAlerts:
    """Tests for admin session alerting."""

    @pytest.mark.asyncio
    async def test_admin_login_triggers_alert(self):
        """Admin login triggers session alert."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.ADMIN_SESSION_CREATED},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            event = create_mock_security_event(
                SecurityEventType.AUTH_SUCCESS,
                actor_type="admin",
                actor_id="admin-1",
            )
            await service.process_security_event(event)

            assert mock_send.call_count == 1
            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.ADMIN_SESSION_CREATED

    @pytest.mark.asyncio
    async def test_user_login_no_alert(self):
        """Regular user login doesn't trigger admin session alert."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.ADMIN_SESSION_CREATED},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            event = create_mock_security_event(
                SecurityEventType.AUTH_SUCCESS,
                actor_type="user",
                actor_id="user-123",
            )
            await service.process_security_event(event)

            mock_send.assert_not_called()


class TestKeyOperationAlerts:
    """Tests for key operation alerting."""

    @pytest.mark.asyncio
    async def test_key_operation_triggers_alert(self):
        """Key operations trigger alerts."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.KEY_OPERATION},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            event = create_mock_security_event(
                SecurityEventType.KEY_GENERATED,
            )
            event = SecurityEventPayload(
                event_type=SecurityEventType.KEY_GENERATED,
                actor=SecurityActor(actor_id="system:keygen", actor_type="system"),
                action="key operation: generate",
                details={"operation": "generate", "key_type": "signing"},
            )
            await service.process_security_event(event)

            assert mock_send.call_count == 1
            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.KEY_OPERATION
            assert call_args.severity == AlertSeverity.HIGH


class TestIntegrityAlerts:
    """Tests for integrity-related alerting."""

    @pytest.mark.asyncio
    async def test_send_integrity_alert(self):
        """Integrity alerts can be sent directly."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            enabled_events={AlertEventType.AUDIT_CHAIN_BROKEN},
        )
        service = AlertingService(config)

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = AlertResult(
                success=True,
                channel=AlertChannel.WEBHOOK,
                alert_id="test",
            )

            results = await service.send_integrity_alert(
                alert_type=AlertEventType.AUDIT_CHAIN_BROKEN,
                title="Audit chain integrity failure",
                description="Hash chain verification failed in SECURITY stream",
                details={"stream": "security", "seq_no": 42},
            )

            assert len(results) == 1
            assert results[0].success is True

            call_args = mock_send.call_args[0][0]
            assert call_args.event_type == AlertEventType.AUDIT_CHAIN_BROKEN
            assert call_args.severity == AlertSeverity.CRITICAL


class TestWebhookDelivery:
    """Tests for webhook alert delivery."""

    @pytest.mark.asyncio
    async def test_successful_webhook_delivery(self):
        """Successful webhook delivery returns success result."""
        config = AlertingConfig(webhook_url="https://example.com/webhook")
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.CONFIG_CHANGED,
            severity=AlertSeverity.MEDIUM,
            title="Test",
            description="Test alert",
        )

        with patch.object(service, "_get_http_client", new_callable=AsyncMock) as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            result = await service._send_webhook(alert)

            assert result.success is True
            assert result.channel == AlertChannel.WEBHOOK
            assert result.error is None

    @pytest.mark.asyncio
    async def test_failed_webhook_delivery(self):
        """Failed webhook delivery returns failure result."""
        config = AlertingConfig(webhook_url="https://example.com/webhook")
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.CONFIG_CHANGED,
            severity=AlertSeverity.MEDIUM,
            title="Test",
            description="Test alert",
        )

        with patch.object(service, "_get_http_client", new_callable=AsyncMock) as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            result = await service._send_webhook(alert)

            assert result.success is False
            assert "500" in result.error

    @pytest.mark.asyncio
    async def test_webhook_includes_hmac_signature(self):
        """Webhook requests include HMAC signature when secret is configured."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            webhook_secret="test-secret",
        )
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.CONFIG_CHANGED,
            severity=AlertSeverity.MEDIUM,
            title="Test",
            description="Test alert",
        )

        with patch.object(service, "_get_http_client", new_callable=AsyncMock) as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.return_value.post = AsyncMock(return_value=mock_response)

            await service._send_webhook(alert)

            # Check that signature header was included
            call_kwargs = mock_client.return_value.post.call_args
            headers = call_kwargs.kwargs["headers"]
            assert "X-Signature-SHA256" in headers
            assert headers["X-Signature-SHA256"].startswith("sha256=")


class TestRateLimiting:
    """Tests for alert rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_excessive_alerts(self):
        """Rate limiting blocks excessive alerts."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            rate_limit_per_minute=2,
        )
        service = AlertingService(config)

        # Manually trigger rate limit checks
        assert service._check_rate_limit(AlertEventType.CONFIG_CHANGED) is True
        assert service._check_rate_limit(AlertEventType.CONFIG_CHANGED) is True
        # Third one should be blocked
        assert service._check_rate_limit(AlertEventType.CONFIG_CHANGED) is False

    @pytest.mark.asyncio
    async def test_rate_limit_per_event_type(self):
        """Rate limiting is per event type."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            rate_limit_per_minute=1,
        )
        service = AlertingService(config)

        # Each event type has its own limit
        assert service._check_rate_limit(AlertEventType.CONFIG_CHANGED) is True
        assert service._check_rate_limit(AlertEventType.PERMISSION_DENIED) is True

        # But the same type is limited
        assert service._check_rate_limit(AlertEventType.CONFIG_CHANGED) is False


class TestSeverityFiltering:
    """Tests for severity-based filtering."""

    def test_severity_comparison(self):
        """Severity comparison works correctly."""
        config = AlertingConfig()
        service = AlertingService(config)

        # HIGH >= LOW
        assert service._severity_gte(AlertSeverity.HIGH, AlertSeverity.LOW) is True
        # LOW >= HIGH
        assert service._severity_gte(AlertSeverity.LOW, AlertSeverity.HIGH) is False
        # MEDIUM >= MEDIUM
        assert service._severity_gte(AlertSeverity.MEDIUM, AlertSeverity.MEDIUM) is True

    @pytest.mark.asyncio
    async def test_low_severity_skips_high_filter_channel(self):
        """Low severity alerts skip channels with high severity filter."""
        config = AlertingConfig(
            webhook_url="https://example.com/webhook",
            severity_filter={AlertChannel.WEBHOOK: AlertSeverity.HIGH},
        )
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.ADMIN_SESSION_CREATED,
            severity=AlertSeverity.LOW,  # Below filter threshold
            title="Test",
            description="Test alert",
        )

        with patch.object(service, "_send_webhook", new_callable=AsyncMock) as mock_send:
            results = await service._send_alert(alert)

            # Webhook should not be called due to severity filter
            mock_send.assert_not_called()
            assert results == []


class TestEmailDelivery:
    """Tests for email alert delivery."""

    @pytest.mark.asyncio
    async def test_email_not_sent_without_smtp_settings(self):
        """Email alerts require SMTP settings."""
        config = AlertingConfig(
            email_recipients=["admin@example.com"],
        )
        service = AlertingService(config, smtp_settings=None)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.AUDIT_CHAIN_BROKEN,
            severity=AlertSeverity.CRITICAL,
            title="Test",
            description="Test alert",
        )

        result = await service._send_email(alert)

        assert result.success is False
        assert "not configured" in result.error

    def test_email_text_rendering(self):
        """Email text rendering produces expected output."""
        config = AlertingConfig()
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.AUTH_FAILURE_THRESHOLD,
            severity=AlertSeverity.HIGH,
            title="Auth Failures Detected",
            description="Multiple auth failures detected",
            actor_id="user-123",
            details={"failure_count": 5},
        )

        text = service._render_email_text(alert)

        assert "Auth Failures Detected" in text
        assert "HIGH" in text
        assert "user-123" in text
        assert "failure_count: 5" in text

    def test_email_html_rendering(self):
        """Email HTML rendering produces valid HTML."""
        config = AlertingConfig()
        service = AlertingService(config)

        alert = AlertPayload(
            alert_id="alert-123",
            event_type=AlertEventType.AUDIT_CHAIN_BROKEN,
            severity=AlertSeverity.CRITICAL,
            title="Chain Broken",
            description="Audit chain integrity failure",
        )

        html = service._render_email_html(alert)

        assert "<!DOCTYPE html>" in html
        assert "Chain Broken" in html
        assert "CRITICAL" in html
        # Critical severity should have red color
        assert "#dc3545" in html


class TestAlertIdGeneration:
    """Tests for alert ID generation."""

    def test_alert_id_format(self):
        """Generated alert IDs have expected format."""
        config = AlertingConfig()
        service = AlertingService(config)

        alert_id = service._generate_alert_id()

        assert alert_id.startswith("alert-")
        # Format: alert-YYYYMMDDHHMMSS-XXXXXXXX
        parts = alert_id.split("-")
        assert len(parts) == 3
        assert len(parts[1]) == 14  # Timestamp
        assert len(parts[2]) == 8  # Random hex

    def test_alert_ids_are_unique(self):
        """Generated alert IDs are unique."""
        config = AlertingConfig()
        service = AlertingService(config)

        ids = {service._generate_alert_id() for _ in range(100)}

        assert len(ids) == 100


class TestWebhookSignature:
    """Tests for webhook HMAC signature generation."""

    def test_signature_format(self):
        """Signature has expected format."""
        config = AlertingConfig(webhook_secret="test-secret")
        service = AlertingService(config)

        payload = '{"test": "data"}'
        signature = service._compute_webhook_signature(payload, "test-secret")

        assert signature.startswith("sha256=")
        # SHA256 produces 64 hex characters
        assert len(signature) == 7 + 64

    def test_signature_is_deterministic(self):
        """Same payload and secret produce same signature."""
        config = AlertingConfig()
        service = AlertingService(config)

        payload = '{"test": "data"}'
        secret = "test-secret"

        sig1 = service._compute_webhook_signature(payload, secret)
        sig2 = service._compute_webhook_signature(payload, secret)

        assert sig1 == sig2

    def test_different_secrets_produce_different_signatures(self):
        """Different secrets produce different signatures."""
        config = AlertingConfig()
        service = AlertingService(config)

        payload = '{"test": "data"}'

        sig1 = service._compute_webhook_signature(payload, "secret-1")
        sig2 = service._compute_webhook_signature(payload, "secret-2")

        assert sig1 != sig2


class TestCreateAlertingConfigFromEnv:
    """Tests for environment-based config creation."""

    def test_default_values(self):
        """Default values when env vars not set."""
        with patch.dict("os.environ", {}, clear=True):
            config = create_alerting_config_from_env()

            assert config.enabled is True
            assert config.webhook_url is None
            assert config.auth_failure_threshold == 5

    def test_loads_from_env(self):
        """Config loads from environment variables."""
        env = {
            "QERDS_ALERTING__ENABLED": "false",
            "QERDS_ALERTING__WEBHOOK_URL": "https://test.example.com",
            "QERDS_ALERTING__WEBHOOK_SECRET": "my-secret",
            "QERDS_ALERTING__EMAIL_RECIPIENTS": "admin@example.com,security@example.com",
            "QERDS_ALERTING__AUTH_FAILURE_THRESHOLD": "10",
            "QERDS_ALERTING__AUTH_FAILURE_WINDOW": "600",
        }

        with patch.dict("os.environ", env, clear=True):
            config = create_alerting_config_from_env()

            assert config.enabled is False
            assert config.webhook_url == "https://test.example.com"
            assert config.webhook_secret == "my-secret"
            assert config.email_recipients == ["admin@example.com", "security@example.com"]
            assert config.auth_failure_threshold == 10
            assert config.auth_failure_window_seconds == 600


class TestServiceCleanup:
    """Tests for service resource cleanup."""

    @pytest.mark.asyncio
    async def test_close_releases_http_client(self):
        """close() releases HTTP client resources."""
        config = AlertingConfig()
        service = AlertingService(config)

        # Create the client
        await service._get_http_client()
        assert service._http_client is not None

        # Close it
        await service.close()
        assert service._http_client is None


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_security_event(
    event_type: SecurityEventType,
    actor_id: str = "user-123",
    actor_type: str = "user",
    resource_type: str | None = None,
    resource_id: str | None = None,
) -> SecurityEventPayload:
    """Create a mock security event for testing.

    Args:
        event_type: Type of security event.
        actor_id: Actor identifier.
        actor_type: Type of actor.
        resource_type: Type of resource.
        resource_id: Resource identifier.

    Returns:
        SecurityEventPayload for testing.
    """
    actor = SecurityActor(
        actor_id=actor_id,
        actor_type=actor_type,
        ip_address="192.168.1.1",
    )

    return SecurityEventPayload(
        event_type=event_type,
        actor=actor,
        action=f"test action: {event_type.value}",
        resource_type=resource_type,
        resource_id=resource_id,
        outcome="test",
        details={"event_id": f"evt-{id(event_type)}"},
    )
