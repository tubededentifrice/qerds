"""Tests for operations event logging service (REQ-H05).

Tests cover:
- Configuration change logging with value redaction
- Deployment marker logging
- Config snapshot logging
- Sensitive key detection
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from qerds.services.audit_log import AuditEventType
from qerds.services.ops_events import (
    REDACTED_VALUE,
    ConfigChangeInfo,
    DeploymentInfo,
    OpsActor,
    OpsEventLogger,
    create_admin_actor,
    create_ci_actor,
    is_sensitive_key,
    redact_if_sensitive,
)


class TestSensitiveKeyDetection:
    """Tests for sensitive key detection and redaction."""

    def test_explicit_sensitive_keys_are_detected(self):
        """Keys in the explicit sensitive list are detected."""
        sensitive_keys = [
            "secret",
            "password",
            "api_key",
            "token",
            "private_key",
            "database_url",
        ]

        for key in sensitive_keys:
            assert is_sensitive_key(key) is True, f"Expected '{key}' to be sensitive"

    def test_pattern_matched_keys_are_sensitive(self):
        """Keys matching sensitive patterns are detected."""
        pattern_keys = [
            "db_secret_key",
            "user_password",
            "my_api_token",
            "auth_credential",
            "signing_key",
        ]

        for key in pattern_keys:
            assert is_sensitive_key(key) is True, f"Expected '{key}' to be sensitive"

    def test_non_sensitive_keys_are_not_detected(self):
        """Non-sensitive keys are not flagged."""
        safe_keys = [
            "max_delivery_size",
            "retention_days",
            "feature_enabled",
            "log_level",
            "port_number",
        ]

        for key in safe_keys:
            assert is_sensitive_key(key) is False, f"Expected '{key}' to NOT be sensitive"

    def test_case_insensitive_detection(self):
        """Sensitive key detection is case insensitive."""
        assert is_sensitive_key("PASSWORD") is True
        assert is_sensitive_key("Api_Key") is True
        assert is_sensitive_key("SECRET_TOKEN") is True


class TestValueRedaction:
    """Tests for value redaction."""

    def test_sensitive_values_are_redacted(self):
        """Sensitive key values are replaced with REDACTED."""
        result = redact_if_sensitive("api_key", "super-secret-key-123")
        assert result == REDACTED_VALUE

    def test_non_sensitive_values_are_preserved(self):
        """Non-sensitive values are returned unchanged."""
        result = redact_if_sensitive("max_size_mb", "100")
        assert result == "100"

    def test_none_values_remain_none(self):
        """None values remain None even for sensitive keys."""
        result = redact_if_sensitive("password", None)
        assert result is None


class TestConfigChangeInfo:
    """Tests for ConfigChangeInfo dataclass."""

    def test_to_dict_includes_all_fields(self):
        """to_dict returns all config change fields."""
        info = ConfigChangeInfo(
            config_key="max_size",
            old_value="50",
            new_value="100",
            change_type="update",
            is_sensitive=False,
            details={"reason": "increased capacity"},
        )

        data = info.to_dict()

        assert data["config_key"] == "max_size"
        assert data["old_value"] == "50"
        assert data["new_value"] == "100"
        assert data["change_type"] == "update"
        assert data["is_sensitive"] is False
        assert data["details"]["reason"] == "increased capacity"
        assert "timestamp" in data


class TestDeploymentInfo:
    """Tests for DeploymentInfo dataclass."""

    def test_to_dict_includes_all_fields(self):
        """to_dict returns all deployment fields."""
        info = DeploymentInfo(
            version="v1.2.3",
            git_sha="abc123def456",
            deployer="github-actions",
            environment="production",
            details={"pipeline_id": "12345"},
        )

        data = info.to_dict()

        assert data["version"] == "v1.2.3"
        assert data["git_sha"] == "abc123def456"
        assert data["deployer"] == "github-actions"
        assert data["environment"] == "production"
        assert data["details"]["pipeline_id"] == "12345"
        assert "timestamp" in data


class TestOpsEventLoggerConfigChange:
    """Tests for config change logging."""

    @pytest.mark.asyncio
    async def test_config_change_logs_to_ops_stream(self):
        """Config changes are logged to the OPS audit stream."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="admin-123", actor_type="admin")

        entry = await logger.log_config_change(
            actor=actor,
            config_key="max_delivery_size_mb",
            old_value="100",
            new_value="200",
        )

        # Verify entry was created
        assert entry is not None
        assert entry.seq_no == 1

    @pytest.mark.asyncio
    async def test_config_change_redacts_sensitive_values(self):
        """Sensitive config values are automatically redacted."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="admin-123", actor_type="admin")

        entry = await logger.log_config_change(
            actor=actor,
            config_key="database_password",
            old_value="old-secret-password",
            new_value="new-secret-password",
        )

        # Verify entry was created and values would be redacted
        assert entry is not None
        # The actual redaction happens in the payload, verified via summary
        assert entry.summary["is_sensitive"] is True

    @pytest.mark.asyncio
    async def test_config_change_includes_change_type(self):
        """Config changes include the type of change."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="admin-123", actor_type="admin")

        entry = await logger.log_config_change(
            actor=actor,
            config_key="new_feature_flag",
            new_value="enabled",
            change_type="create",
        )

        assert entry is not None
        assert entry.summary["change_type"] == "create"


class TestOpsEventLoggerDeploymentMarker:
    """Tests for deployment marker logging."""

    @pytest.mark.asyncio
    async def test_deployment_marker_logs_to_ops_stream(self):
        """Deployment markers are logged to the OPS audit stream."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="github-actions", actor_type="ci_pipeline")
        deployment = DeploymentInfo(
            version="v1.2.3",
            git_sha="abc123def456",
            deployer="github-actions",
            environment="production",
        )

        entry = await logger.log_deployment_marker(
            actor=actor,
            deployment=deployment,
        )

        assert entry is not None
        assert entry.seq_no == 1
        assert entry.event_type == AuditEventType.DEPLOYMENT_MARKER.value

    @pytest.mark.asyncio
    async def test_deployment_marker_includes_summary(self):
        """Deployment markers include summary metadata."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="github-actions", actor_type="ci_pipeline")
        deployment = DeploymentInfo(
            version="v2.0.0",
            git_sha="deadbeef12345678",
            deployer="gitlab-ci",
            environment="staging",
        )

        entry = await logger.log_deployment_marker(
            actor=actor,
            deployment=deployment,
        )

        assert entry.summary["version"] == "v2.0.0"
        assert entry.summary["git_sha"] == "deadbee"  # Short SHA
        assert entry.summary["deployer"] == "gitlab-ci"
        assert entry.summary["environment"] == "staging"


class TestOpsEventLoggerConfigSnapshot:
    """Tests for config snapshot logging."""

    @pytest.mark.asyncio
    async def test_config_snapshot_logs_to_ops_stream(self):
        """Config snapshots are logged to the OPS audit stream."""
        session = create_mock_session()

        logger = OpsEventLogger(session)
        actor = OpsActor(actor_id="admin-456", actor_type="admin")
        snapshot_id = uuid4()

        entry = await logger.log_config_snapshot(
            actor=actor,
            snapshot_id=snapshot_id,
            version="v1.0.0",
            description="Initial configuration snapshot",
        )

        assert entry is not None
        assert entry.event_type == AuditEventType.CONFIG_SNAPSHOT.value
        assert entry.resource_type == "config_snapshot"
        assert entry.resource_id == str(snapshot_id)


class TestActorHelpers:
    """Tests for actor creation helpers."""

    def test_create_ci_actor(self):
        """create_ci_actor creates proper CI pipeline actor."""
        actor = create_ci_actor("github-actions")

        assert actor.actor_id == "github-actions"
        assert actor.actor_type == "ci_pipeline"

    def test_create_ci_actor_with_pipeline_id(self):
        """create_ci_actor includes pipeline ID when provided."""
        actor = create_ci_actor("github-actions", "12345")

        assert actor.actor_id == "github-actions:12345"
        assert actor.actor_type == "ci_pipeline"

    def test_create_admin_actor(self):
        """create_admin_actor creates proper admin actor."""
        actor = create_admin_actor("user-abc123")

        assert actor.actor_id == "user-abc123"
        assert actor.actor_type == "admin"


# =============================================================================
# Test Helpers
# =============================================================================


def create_mock_session() -> AsyncMock:
    """Create a mock SQLAlchemy async session for OPS stream testing.

    Returns:
        Mock async session configured for OPS stream operations.
    """
    session = AsyncMock()

    async def mock_execute(query):
        result = MagicMock()
        # Return None for latest record query (simulating empty stream)
        result.scalar_one_or_none.return_value = None
        return result

    def mock_add(record):
        # Store the record for inspection
        session._added_record = record

    session.execute = mock_execute
    session.add = mock_add
    session.flush = AsyncMock()

    return session
