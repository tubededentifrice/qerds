"""Tests for security event logging service.

Tests cover:
- SecurityEventType enumeration completeness
- SecurityEventPayload construction
- SecurityEventLogger logging methods
- Event querying and filtering
- Export functionality
- Integration with AuditLogService
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import AuditEventType, AuditLogEntry
from qerds.services.security_events import (
    AuthOutcome,
    AuthzOutcome,
    SecurityActor,
    SecurityEventLogger,
    SecurityEventPayload,
    SecurityEventType,
    create_system_actor,
)


class TestSecurityEventType:
    """Tests for SecurityEventType enumeration."""

    def test_auth_event_types_exist(self):
        """All authentication event types are defined."""
        auth_events = [
            SecurityEventType.AUTH_SUCCESS,
            SecurityEventType.AUTH_FAILURE,
            SecurityEventType.AUTH_LOGOUT,
            SecurityEventType.AUTH_TOKEN_REFRESH,
            SecurityEventType.AUTH_MFA_CHALLENGE,
            SecurityEventType.AUTH_MFA_SUCCESS,
            SecurityEventType.AUTH_MFA_FAILURE,
            SecurityEventType.AUTH_SESSION_EXPIRED,
        ]
        assert all(e.value for e in auth_events)

    def test_authz_event_types_exist(self):
        """All authorization event types are defined."""
        authz_events = [
            SecurityEventType.AUTHZ_GRANTED,
            SecurityEventType.AUTHZ_DENIED,
            SecurityEventType.AUTHZ_ELEVATED,
        ]
        assert all(e.value for e in authz_events)

    def test_admin_event_types_exist(self):
        """All admin action event types are defined."""
        admin_events = [
            SecurityEventType.ADMIN_ACTION,
            SecurityEventType.ADMIN_USER_CREATED,
            SecurityEventType.ADMIN_USER_MODIFIED,
            SecurityEventType.ADMIN_USER_DISABLED,
            SecurityEventType.ADMIN_ROLE_ASSIGNED,
            SecurityEventType.ADMIN_ROLE_REVOKED,
        ]
        assert all(e.value for e in admin_events)

    def test_key_event_types_exist(self):
        """All key operation event types are defined."""
        key_events = [
            SecurityEventType.KEY_GENERATED,
            SecurityEventType.KEY_ROTATED,
            SecurityEventType.KEY_REVOKED,
            SecurityEventType.KEY_EXPORTED,
            SecurityEventType.KEY_IMPORTED,
        ]
        assert all(e.value for e in key_events)

    def test_config_event_types_exist(self):
        """All configuration event types are defined."""
        config_events = [
            SecurityEventType.CONFIG_CHANGED,
            SecurityEventType.CONFIG_ROLLBACK,
        ]
        assert all(e.value for e in config_events)

    def test_sensitive_access_event_types_exist(self):
        """All sensitive data access event types are defined."""
        sensitive_events = [
            SecurityEventType.SENSITIVE_ACCESS,
            SecurityEventType.SENSITIVE_EXPORT,
            SecurityEventType.EVIDENCE_ACCESSED,
            SecurityEventType.AUDIT_LOG_ACCESSED,
        ]
        assert all(e.value for e in sensitive_events)

    def test_dual_control_event_types_exist(self):
        """All dual-control event types are defined."""
        dual_control_events = [
            SecurityEventType.DUAL_CONTROL_REQUESTED,
            SecurityEventType.DUAL_CONTROL_APPROVED,
            SecurityEventType.DUAL_CONTROL_REJECTED,
        ]
        assert all(e.value for e in dual_control_events)


class TestAuthOutcome:
    """Tests for AuthOutcome enumeration."""

    def test_all_outcomes_defined(self):
        """All authentication outcomes are defined."""
        outcomes = [
            AuthOutcome.SUCCESS,
            AuthOutcome.FAILURE,
            AuthOutcome.LOCKED,
            AuthOutcome.EXPIRED,
            AuthOutcome.MFA_REQUIRED,
        ]
        assert all(o.value for o in outcomes)


class TestAuthzOutcome:
    """Tests for AuthzOutcome enumeration."""

    def test_all_outcomes_defined(self):
        """All authorization outcomes are defined."""
        outcomes = [
            AuthzOutcome.GRANTED,
            AuthzOutcome.DENIED,
            AuthzOutcome.ELEVATED,
        ]
        assert all(o.value for o in outcomes)


class TestSecurityActor:
    """Tests for SecurityActor dataclass."""

    def test_minimal_actor(self):
        """Actor can be created with minimal fields."""
        actor = SecurityActor(
            actor_id="user-123",
            actor_type="user",
        )
        assert actor.actor_id == "user-123"
        assert actor.actor_type == "user"
        assert actor.ip_address is None
        assert actor.user_agent is None
        assert actor.session_id is None

    def test_full_actor(self):
        """Actor can be created with all fields."""
        actor = SecurityActor(
            actor_id="user-456",
            actor_type="admin",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            session_id="sess-789",
        )
        assert actor.actor_id == "user-456"
        assert actor.actor_type == "admin"
        assert actor.ip_address == "192.168.1.100"
        assert actor.user_agent == "Mozilla/5.0"
        assert actor.session_id == "sess-789"

    def test_actor_is_immutable(self):
        """Actor dataclass is frozen (immutable)."""
        actor = SecurityActor(actor_id="user-123", actor_type="user")
        with pytest.raises(AttributeError):
            actor.actor_id = "changed"  # type: ignore


class TestSecurityEventPayload:
    """Tests for SecurityEventPayload dataclass."""

    def test_minimal_payload(self):
        """Payload can be created with minimal fields."""
        actor = SecurityActor(actor_id="user-123", actor_type="user")
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="login",
        )
        assert payload.event_type == SecurityEventType.AUTH_SUCCESS
        assert payload.actor == actor
        assert payload.action == "login"
        assert payload.resource_type is None
        assert payload.outcome is None

    def test_full_payload(self):
        """Payload can be created with all fields."""
        actor = SecurityActor(actor_id="user-123", actor_type="user")
        details = {"method": "password", "mfa": True}
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="authenticate",
            resource_type="session",
            resource_id="sess-456",
            outcome="success",
            details=details,
            timestamp=timestamp,
        )

        assert payload.resource_type == "session"
        assert payload.resource_id == "sess-456"
        assert payload.outcome == "success"
        assert payload.details == details
        assert payload.timestamp == timestamp

    def test_payload_to_dict(self):
        """Payload converts to dictionary correctly."""
        actor = SecurityActor(
            actor_id="user-123",
            actor_type="user",
            ip_address="192.168.1.1",
            user_agent="TestAgent",
            session_id="sess-789",
        )
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="login",
            resource_type="session",
            resource_id="sess-456",
            outcome="success",
            details={"key": "value"},
            timestamp=timestamp,
        )

        result = payload.to_dict()

        assert result["event_type"] == "auth_success"
        assert result["actor"]["actor_id"] == "user-123"
        assert result["actor"]["actor_type"] == "user"
        assert result["actor"]["ip_address"] == "192.168.1.1"
        assert result["actor"]["user_agent"] == "TestAgent"
        assert result["actor"]["session_id"] == "sess-789"
        assert result["action"] == "login"
        assert result["resource_type"] == "session"
        assert result["resource_id"] == "sess-456"
        assert result["outcome"] == "success"
        assert result["details"] == {"key": "value"}
        assert result["timestamp"] == "2024-01-15T10:30:00+00:00"

    def test_payload_is_immutable(self):
        """Payload dataclass is frozen (immutable)."""
        actor = SecurityActor(actor_id="user-123", actor_type="user")
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="login",
        )
        with pytest.raises(AttributeError):
            payload.action = "changed"  # type: ignore


class TestCreateSystemActor:
    """Tests for create_system_actor helper."""

    def test_default_system_actor(self):
        """Creates system actor with defaults."""
        actor = create_system_actor()
        assert actor.actor_id == "system:system"
        assert actor.actor_type == "system"
        assert actor.ip_address == "127.0.0.1"

    def test_custom_component_actor(self):
        """Creates system actor with custom component."""
        actor = create_system_actor(component="scheduler", ip_address="10.0.0.1")
        assert actor.actor_id == "system:scheduler"
        assert actor.actor_type == "system"
        assert actor.ip_address == "10.0.0.1"


class TestSecurityEventLoggerLogEvent:
    """Tests for SecurityEventLogger.log_event method."""

    @pytest.mark.asyncio
    async def test_log_event_calls_audit_service(self):
        """log_event delegates to AuditLogService.append."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        # Mock the internal audit service
        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="login",
        )

        result = await logger.log_event(payload)

        assert result == mock_entry
        logger._audit_service.append.assert_called_once()

        # Verify the call parameters
        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["stream"] == AuditStream.SECURITY
        assert call_kwargs["actor_type"] == "user"
        assert call_kwargs["actor_id"] == "user-123"

    @pytest.mark.asyncio
    async def test_log_event_maps_event_type(self):
        """log_event maps SecurityEventType to AuditEventType."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")
        payload = SecurityEventPayload(
            event_type=SecurityEventType.AUTH_SUCCESS,
            actor=actor,
            action="login",
        )

        await logger.log_event(payload)

        call_kwargs = logger._audit_service.append.call_args.kwargs
        # AUTH_SUCCESS should map to auth_login
        assert call_kwargs["event_type"] == AuditEventType.AUTH_LOGIN.value


class TestSecurityEventLoggerAuthEvents:
    """Tests for authentication event logging."""

    @pytest.mark.asyncio
    async def test_log_auth_event_success(self):
        """Logs successful authentication."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(
            actor_id="user-123",
            actor_type="user",
            ip_address="192.168.1.1",
        )

        result = await logger.log_auth_event(
            actor=actor,
            outcome=AuthOutcome.SUCCESS,
            method="password",
        )

        assert result == mock_entry
        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTH_LOGIN.value

    @pytest.mark.asyncio
    async def test_log_auth_event_failure(self):
        """Logs failed authentication."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")

        await logger.log_auth_event(
            actor=actor,
            outcome=AuthOutcome.FAILURE,
            method="password",
            details={"reason": "invalid_password"},
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTH_FAILED.value

    @pytest.mark.asyncio
    async def test_log_auth_event_mfa_required(self):
        """Logs MFA challenge requirement."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")

        await logger.log_auth_event(
            actor=actor,
            outcome=AuthOutcome.MFA_REQUIRED,
            method="password",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTH_MFA_CHALLENGE.value

    @pytest.mark.asyncio
    async def test_log_auth_logout(self):
        """Logs user logout."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")

        await logger.log_auth_logout(
            actor=actor,
            session_id="sess-456",
            reason="user_initiated",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTH_LOGOUT.value
        assert call_kwargs["resource_id"] == "sess-456"


class TestSecurityEventLoggerAuthzEvents:
    """Tests for authorization event logging."""

    @pytest.mark.asyncio
    async def test_log_authz_granted(self):
        """Logs granted authorization."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")

        await logger.log_authz_event(
            actor=actor,
            permission="view_delivery",
            resource_type="delivery",
            resource_id="del-456",
            outcome=AuthzOutcome.GRANTED,
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTHZ_GRANTED.value
        assert call_kwargs["resource_type"] == "delivery"
        assert call_kwargs["resource_id"] == "del-456"

    @pytest.mark.asyncio
    async def test_log_authz_denied(self):
        """Logs denied authorization."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="user-123", actor_type="user")

        await logger.log_authz_event(
            actor=actor,
            permission="admin_access",
            outcome=AuthzOutcome.DENIED,
            details={"reason": "insufficient_role"},
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.AUTHZ_DENIED.value


class TestSecurityEventLoggerAdminEvents:
    """Tests for admin action logging."""

    @pytest.mark.asyncio
    async def test_log_admin_action(self):
        """Logs generic admin action."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_admin_action(
            actor=actor,
            action="bulk_delete",
            target_type="deliveries",
            target_id="batch-123",
            details={"count": 50},
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.ADMIN_ACTION.value
        assert call_kwargs["resource_type"] == "deliveries"
        assert call_kwargs["resource_id"] == "batch-123"

    @pytest.mark.asyncio
    async def test_log_user_management_create(self):
        """Logs user creation."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_user_management(
            actor=actor,
            action="create",
            target_user_id="user-new",
            changes={"email": "new@example.com"},
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        # Expect the audit event type, not the security event type
        assert "admin" in call_kwargs["event_type"] or "user" in call_kwargs["event_type"]
        assert call_kwargs["resource_type"] == "user"
        assert call_kwargs["resource_id"] == "user-new"

    @pytest.mark.asyncio
    async def test_log_role_assign(self):
        """Logs role assignment."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_role_change(
            actor=actor,
            target_user_id="user-123",
            role="auditor",
            action="assign",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_type"] == "user"
        assert call_kwargs["resource_id"] == "user-123"

    @pytest.mark.asyncio
    async def test_log_role_revoke(self):
        """Logs role revocation."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_role_change(
            actor=actor,
            target_user_id="user-123",
            role="admin",
            action="revoke",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_type"] == "user"


class TestSecurityEventLoggerKeyEvents:
    """Tests for key operation logging."""

    @pytest.mark.asyncio
    async def test_log_key_generate(self):
        """Logs key generation."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="system:keygen", actor_type="system")

        await logger.log_key_operation(
            actor=actor,
            operation="generate",
            key_type="signing",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.KEY_GENERATED.value
        assert call_kwargs["resource_type"] == "key"

    @pytest.mark.asyncio
    async def test_log_key_rotate(self):
        """Logs key rotation."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_key_operation(
            actor=actor,
            operation="rotate",
            key_id="key-old",
            key_type="encryption",
            details={"new_key_id": "key-new"},
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.KEY_ROTATED.value
        assert call_kwargs["resource_id"] == "key-old"


class TestSecurityEventLoggerConfigEvents:
    """Tests for configuration change logging."""

    @pytest.mark.asyncio
    async def test_log_config_change(self):
        """Logs configuration change."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_config_change(
            actor=actor,
            config_key="retention_days",
            old_value="30",
            new_value="60",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["event_type"] == AuditEventType.CONFIG_CHANGED.value
        assert call_kwargs["resource_type"] == "config"
        assert call_kwargs["resource_id"] == "retention_days"


class TestSecurityEventLoggerSensitiveAccess:
    """Tests for sensitive data access logging."""

    @pytest.mark.asyncio
    async def test_log_evidence_access(self):
        """Logs evidence access."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="auditor-1", actor_type="auditor")

        await logger.log_sensitive_access(
            actor=actor,
            resource_type="evidence",
            resource_id="ev-123",
            access_type="read",
            purpose="audit_review",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        # Should use EVIDENCE_ACCESSED for evidence resource type
        assert call_kwargs["resource_type"] == "evidence"
        assert call_kwargs["resource_id"] == "ev-123"

    @pytest.mark.asyncio
    async def test_log_audit_log_access(self):
        """Logs audit log access."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="auditor-1", actor_type="auditor")

        await logger.log_sensitive_access(
            actor=actor,
            resource_type="audit_log",
            resource_id="security-stream",
            access_type="export",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_type"] == "audit_log"


class TestSecurityEventLoggerDualControl:
    """Tests for dual-control event logging."""

    @pytest.mark.asyncio
    async def test_log_dual_control_request(self):
        """Logs dual-control request creation."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        await logger.log_dual_control_request(
            actor=actor,
            request_id="req-123",
            operation="key_rotation",
            permission="key_management",
            reason="Scheduled rotation",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_type"] == "dual_control_request"
        assert call_kwargs["resource_id"] == "req-123"

    @pytest.mark.asyncio
    async def test_log_dual_control_approve(self):
        """Logs dual-control approval."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-2", actor_type="admin")

        await logger.log_dual_control_decision(
            actor=actor,
            request_id="req-123",
            decision="approve",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_id"] == "req-123"

    @pytest.mark.asyncio
    async def test_log_dual_control_reject(self):
        """Logs dual-control rejection."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entry = create_mock_audit_entry()
        logger._audit_service.append = AsyncMock(return_value=mock_entry)

        actor = SecurityActor(actor_id="admin-2", actor_type="admin")

        await logger.log_dual_control_decision(
            actor=actor,
            request_id="req-123",
            decision="reject",
            reason="Insufficient justification",
        )

        call_kwargs = logger._audit_service.append.call_args.kwargs
        assert call_kwargs["resource_id"] == "req-123"


class TestSecurityEventLoggerQuery:
    """Tests for event querying."""

    @pytest.mark.asyncio
    async def test_get_events_delegates_to_audit_service(self):
        """get_events delegates to AuditLogService.get_records."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entries = [create_mock_audit_entry()]
        logger._audit_service.get_records = AsyncMock(return_value=mock_entries)

        result = await logger.get_events(
            actor_id="user-123",
            limit=50,
        )

        assert result == mock_entries
        logger._audit_service.get_records.assert_called_once()

        call_kwargs = logger._audit_service.get_records.call_args.kwargs
        assert call_kwargs["stream"] == AuditStream.SECURITY
        assert call_kwargs["actor_id"] == "user-123"
        assert call_kwargs["limit"] == 50


class TestSecurityEventLoggerExport:
    """Tests for event export functionality."""

    @pytest.mark.asyncio
    async def test_export_events_includes_records(self):
        """export_events includes event records."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entries = [
            create_mock_audit_entry(seq_no=1),
            create_mock_audit_entry(seq_no=2),
        ]
        logger._audit_service.get_records = AsyncMock(return_value=mock_entries)
        logger._audit_service.verify_chain = AsyncMock(
            return_value=MagicMock(
                valid=True,
                checked_records=2,
                first_seq_no=1,
                last_seq_no=2,
                errors=[],
            )
        )

        result = await logger.export_events(include_verification=True)

        assert result["stream"] == "security"
        assert result["record_count"] == 2
        assert len(result["events"]) == 2
        assert "verification" in result
        assert result["verification"]["valid"] is True

    @pytest.mark.asyncio
    async def test_export_events_without_verification(self):
        """export_events can skip verification."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        mock_entries = [create_mock_audit_entry()]
        logger._audit_service.get_records = AsyncMock(return_value=mock_entries)
        # Mock verify_chain to track if it's called
        logger._audit_service.verify_chain = AsyncMock()

        result = await logger.export_events(include_verification=False)

        assert "verification" not in result
        logger._audit_service.verify_chain.assert_not_called()


class TestEventTypeMapping:
    """Tests for event type mapping."""

    def test_maps_known_security_events_to_audit_events(self):
        """Known SecurityEventTypes map to AuditEventTypes."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        # Test a selection of mappings
        mappings = [
            (SecurityEventType.AUTH_SUCCESS, AuditEventType.AUTH_LOGIN.value),
            (SecurityEventType.AUTH_FAILURE, AuditEventType.AUTH_FAILED.value),
            (SecurityEventType.AUTH_LOGOUT, AuditEventType.AUTH_LOGOUT.value),
            (SecurityEventType.AUTHZ_GRANTED, AuditEventType.AUTHZ_GRANTED.value),
            (SecurityEventType.AUTHZ_DENIED, AuditEventType.AUTHZ_DENIED.value),
            (SecurityEventType.KEY_GENERATED, AuditEventType.KEY_GENERATED.value),
            (SecurityEventType.CONFIG_CHANGED, AuditEventType.CONFIG_CHANGED.value),
        ]

        for security_type, expected_audit_type in mappings:
            result = logger._map_to_audit_event_type(security_type)
            assert result == expected_audit_type, f"Failed for {security_type}"

    def test_unmapped_events_use_security_type_value(self):
        """Unmapped SecurityEventTypes use their own value."""
        session = AsyncMock()
        logger = SecurityEventLogger(session)

        # These don't have direct AuditEventType equivalents
        unmapped_types = [
            SecurityEventType.AUTH_TOKEN_REFRESH,
            SecurityEventType.AUTH_MFA_SUCCESS,
            SecurityEventType.DUAL_CONTROL_REQUESTED,
            SecurityEventType.SENSITIVE_ACCESS,
        ]

        for event_type in unmapped_types:
            result = logger._map_to_audit_event_type(event_type)
            assert result == event_type.value


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_audit_entry(
    seq_no: int = 1,
    event_type: str = "auth_login",
) -> AuditLogEntry:
    """Create a mock AuditLogEntry for testing.

    Args:
        seq_no: Sequence number.
        event_type: Event type string.

    Returns:
        Mock AuditLogEntry.
    """
    return AuditLogEntry(
        record_id=uuid4(),
        stream=AuditStream.SECURITY,
        seq_no=seq_no,
        record_hash="a" * 64,
        prev_record_hash=None if seq_no == 1 else "b" * 64,
        event_type=event_type,
        actor_type="user",
        actor_id="user-123",
        resource_type=None,
        resource_id=None,
        payload_ref="inline:test:abc",
        summary=None,
        created_at=datetime.now(UTC),
    )
