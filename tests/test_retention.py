"""Tests for retention policy management and enforcement.

Tests cover:
- RetentionPolicyService CRUD operations
- CPCE minimum retention enforcement
- RetentionEnforcementService artifact processing
- Worker handler integration
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qerds.db.models.base import RetentionActionType
from qerds.services.retention import (
    CPCE_MINIMUM_RETENTION_DAYS,
    ArtifactType,
    CPCEViolationError,
    EligibleArtifact,
    RetentionActionResult,
    RetentionEnforcementService,
    RetentionPolicyService,
    create_default_cpce_policies,
)
from qerds.worker.handlers.retention import enforce_retention_handler


class TestArtifactType:
    """Tests for ArtifactType enum."""

    def test_artifact_type_values(self) -> None:
        """Verify all artifact type values."""
        assert ArtifactType.DELIVERY.value == "delivery"
        assert ArtifactType.CONTENT_OBJECT.value == "content_object"
        assert ArtifactType.EVIDENCE_OBJECT.value == "evidence_object"
        assert ArtifactType.AUDIT_LOG.value == "audit_log"

    def test_artifact_type_is_string_enum(self) -> None:
        """ArtifactType should be usable as string."""
        assert ArtifactType.DELIVERY == "delivery"
        assert str(ArtifactType.DELIVERY) == "delivery"


class TestRetentionPolicyService:
    """Tests for RetentionPolicyService."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        """Create a mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def service(self, mock_session: AsyncMock) -> RetentionPolicyService:
        """Create service instance with mock session."""
        return RetentionPolicyService(mock_session)

    @pytest.mark.asyncio
    async def test_create_policy_success(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Creating a policy with valid params should succeed."""
        policy = await service.create_policy(
            artifact_type=ArtifactType.CONTENT_OBJECT.value,
            retention_days=90,
            expiry_action=RetentionActionType.DELETE,
            description="Test policy",
        )

        assert policy.artifact_type == "content_object"
        assert policy.retention_days == 90
        assert policy.expiry_action == RetentionActionType.DELETE
        assert policy.is_active is True
        mock_session.add.assert_called_once()
        mock_session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_policy_cpce_violation_delivery(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Creating delivery policy under 365 days should raise CPCEViolationError."""
        with pytest.raises(CPCEViolationError) as exc_info:
            await service.create_policy(
                artifact_type=ArtifactType.DELIVERY.value,
                retention_days=180,
                expiry_action=RetentionActionType.ARCHIVE,
            )

        assert "365" in str(exc_info.value)
        assert "delivery" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_policy_cpce_violation_evidence(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Creating evidence policy under 365 days should raise CPCEViolationError."""
        with pytest.raises(CPCEViolationError) as exc_info:
            await service.create_policy(
                artifact_type=ArtifactType.EVIDENCE_OBJECT.value,
                retention_days=364,
                expiry_action=RetentionActionType.ARCHIVE,
            )

        assert "365" in str(exc_info.value)
        assert "evidence_object" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_policy_content_object_short_retention_allowed(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Content objects can have retention under 365 days."""
        policy = await service.create_policy(
            artifact_type=ArtifactType.CONTENT_OBJECT.value,
            retention_days=30,
            expiry_action=RetentionActionType.DELETE,
        )

        assert policy.retention_days == 30

    @pytest.mark.asyncio
    async def test_create_policy_audit_log_short_retention_allowed(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Audit logs can have retention under 365 days (though not recommended)."""
        policy = await service.create_policy(
            artifact_type=ArtifactType.AUDIT_LOG.value,
            retention_days=180,
            expiry_action=RetentionActionType.ARCHIVE,
        )

        assert policy.retention_days == 180

    @pytest.mark.asyncio
    async def test_get_policy_found(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Getting an existing policy should return it."""
        mock_policy = MagicMock()
        mock_policy.id = 1
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_policy
        mock_session.execute.return_value = mock_result

        result = await service.get_policy(1)

        assert result == mock_policy

    @pytest.mark.asyncio
    async def test_get_policy_not_found(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Getting a non-existent policy should return None."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await service.get_policy(999)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_active_policies(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Getting active policies should return list."""
        mock_policies = [MagicMock(), MagicMock()]
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_policies
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await service.get_active_policies()

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_active_policies_filtered(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Getting active policies with filter should apply filter."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        await service.get_active_policies(artifact_type="delivery")

        # Verify execute was called (filter is in the query)
        mock_session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_deactivate_policy_success(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Deactivating an existing policy should succeed."""
        mock_policy = MagicMock()
        mock_policy.is_active = True
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_policy
        mock_session.execute.return_value = mock_result

        result = await service.deactivate_policy(1)

        assert result is True
        assert mock_policy.is_active is False
        mock_session.flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_deactivate_policy_not_found(
        self,
        service: RetentionPolicyService,
        mock_session: AsyncMock,
    ) -> None:
        """Deactivating a non-existent policy should return False."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await service.deactivate_policy(999)

        assert result is False

    def test_calculate_retention_deadline(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Retention deadline should be created_at + retention_days."""
        created_at = datetime(2024, 1, 1, tzinfo=UTC)
        deadline = service.calculate_retention_deadline(created_at, 365)

        expected = datetime(2025, 1, 1, tzinfo=UTC)
        assert deadline == expected

    def test_is_past_minimum_retention_true(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Artifact older than 365 days should be past minimum retention."""
        created_at = datetime(2023, 1, 1, tzinfo=UTC)
        now = datetime(2024, 6, 1, tzinfo=UTC)

        assert service.is_past_minimum_retention(created_at, now) is True

    def test_is_past_minimum_retention_false(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Artifact younger than 365 days should not be past minimum retention."""
        created_at = datetime(2024, 1, 1, tzinfo=UTC)
        now = datetime(2024, 6, 1, tzinfo=UTC)

        assert service.is_past_minimum_retention(created_at, now) is False

    def test_is_past_minimum_retention_exact_boundary(
        self,
        service: RetentionPolicyService,
    ) -> None:
        """Artifact exactly 365 days old should be past minimum retention."""
        created_at = datetime(2024, 1, 1, tzinfo=UTC)
        now = created_at + timedelta(days=365)

        assert service.is_past_minimum_retention(created_at, now) is True


class TestEligibleArtifact:
    """Tests for EligibleArtifact dataclass."""

    def test_create_eligible_artifact(self) -> None:
        """Creating an EligibleArtifact should set all fields."""
        now = datetime.now(UTC)
        deadline = now + timedelta(days=365)

        artifact = EligibleArtifact(
            artifact_type="delivery",
            artifact_ref="del-123",
            created_at=now,
            retention_deadline=deadline,
            metadata={"key": "value"},
        )

        assert artifact.artifact_type == "delivery"
        assert artifact.artifact_ref == "del-123"
        assert artifact.created_at == now
        assert artifact.retention_deadline == deadline
        assert artifact.metadata == {"key": "value"}

    def test_eligible_artifact_is_frozen(self) -> None:
        """EligibleArtifact should be immutable."""
        artifact = EligibleArtifact(
            artifact_type="delivery",
            artifact_ref="del-123",
            created_at=datetime.now(UTC),
            retention_deadline=datetime.now(UTC),
        )

        with pytest.raises(AttributeError):
            artifact.artifact_type = "content_object"  # type: ignore[misc]


class TestRetentionEnforcementService:
    """Tests for RetentionEnforcementService."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        """Create a mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def service(self, mock_session: AsyncMock) -> RetentionEnforcementService:
        """Create service instance with mock session."""
        return RetentionEnforcementService(mock_session)

    @pytest.mark.asyncio
    async def test_find_eligible_artifacts_empty(
        self,
        service: RetentionEnforcementService,
    ) -> None:
        """Finding eligible artifacts should return empty list for now."""
        mock_policy = MagicMock()
        mock_policy.retention_days = 365
        mock_policy.artifact_type = "delivery"

        result = await service.find_eligible_artifacts(mock_policy, limit=100)

        # Current implementation returns empty list (placeholder)
        assert result == []

    @pytest.mark.asyncio
    async def test_execute_action_dry_run(
        self,
        service: RetentionEnforcementService,
    ) -> None:
        """Dry run should succeed without making changes."""
        artifact = EligibleArtifact(
            artifact_type="delivery",
            artifact_ref="del-123",
            created_at=datetime.now(UTC),
            retention_deadline=datetime.now(UTC),
        )
        mock_policy = MagicMock()
        mock_policy.expiry_action = RetentionActionType.ARCHIVE
        mock_policy.id = 1

        result = await service.execute_action(
            artifact=artifact,
            policy=mock_policy,
            dry_run=True,
        )

        assert result.success is True
        assert result.action_type == RetentionActionType.ARCHIVE
        assert result.archive_ref is None

    @pytest.mark.asyncio
    async def test_execute_action_archive(
        self,
        service: RetentionEnforcementService,
        mock_session: AsyncMock,
    ) -> None:
        """Archive action should create archive reference."""
        artifact = EligibleArtifact(
            artifact_type="delivery",
            artifact_ref="del-123",
            created_at=datetime.now(UTC),
            retention_deadline=datetime.now(UTC),
        )
        mock_policy = MagicMock()
        mock_policy.expiry_action = RetentionActionType.ARCHIVE
        mock_policy.id = 1

        # Mock the audit service
        with patch.object(service._audit_service, "append", new_callable=AsyncMock):
            result = await service.execute_action(
                artifact=artifact,
                policy=mock_policy,
                dry_run=False,
            )

        assert result.success is True
        assert result.action_type == RetentionActionType.ARCHIVE
        assert result.archive_ref is not None
        assert "archive/" in result.archive_ref

    @pytest.mark.asyncio
    async def test_execute_action_delete(
        self,
        service: RetentionEnforcementService,
        mock_session: AsyncMock,
    ) -> None:
        """Delete action should succeed."""
        artifact = EligibleArtifact(
            artifact_type="content_object",
            artifact_ref="co-456",
            created_at=datetime.now(UTC),
            retention_deadline=datetime.now(UTC),
        )
        mock_policy = MagicMock()
        mock_policy.expiry_action = RetentionActionType.DELETE
        mock_policy.id = 2

        # Mock the audit service
        with patch.object(service._audit_service, "append", new_callable=AsyncMock):
            result = await service.execute_action(
                artifact=artifact,
                policy=mock_policy,
                dry_run=False,
            )

        assert result.success is True
        assert result.action_type == RetentionActionType.DELETE
        assert result.archive_ref is None

    @pytest.mark.asyncio
    async def test_get_action_history(
        self,
        service: RetentionEnforcementService,
        mock_session: AsyncMock,
    ) -> None:
        """Getting action history should return list."""
        mock_actions = [MagicMock(), MagicMock()]
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_actions
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        result = await service.get_action_history()

        assert len(result) == 2


class TestEnforceRetentionHandler:
    """Tests for the worker handler."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        """Create a mock database session."""
        return AsyncMock()

    @pytest.fixture
    def mock_job(self) -> MagicMock:
        """Create a mock job."""
        job = MagicMock()
        job.payload_json = {}
        return job

    @pytest.mark.asyncio
    async def test_handler_no_policies(
        self,
        mock_session: AsyncMock,
        mock_job: MagicMock,
    ) -> None:
        """Handler should return zeros when no policies exist."""
        with (
            patch(
                "qerds.worker.handlers.retention.RetentionPolicyService"
            ) as mock_policy_cls,
            patch("qerds.worker.handlers.retention.RetentionEnforcementService"),
            patch("qerds.worker.handlers.retention.AuditLogService"),
        ):
            mock_policy_service = AsyncMock()
            mock_policy_service.get_active_policies.return_value = []
            mock_policy_cls.return_value = mock_policy_service

            result = await enforce_retention_handler(mock_session, mock_job)

        assert result["processed"] == 0
        assert result["archived"] == 0
        assert result["deleted"] == 0
        assert result["dry_run"] is False

    @pytest.mark.asyncio
    async def test_handler_dry_run(
        self,
        mock_session: AsyncMock,
        mock_job: MagicMock,
    ) -> None:
        """Handler should respect dry_run flag."""
        mock_job.payload_json = {"dry_run": True}

        with (
            patch(
                "qerds.worker.handlers.retention.RetentionPolicyService"
            ) as mock_policy_cls,
            patch("qerds.worker.handlers.retention.RetentionEnforcementService"),
            patch("qerds.worker.handlers.retention.AuditLogService"),
        ):
            mock_policy_service = AsyncMock()
            mock_policy_service.get_active_policies.return_value = []
            mock_policy_cls.return_value = mock_policy_service

            result = await enforce_retention_handler(mock_session, mock_job)

        assert result["dry_run"] is True

    @pytest.mark.asyncio
    async def test_handler_with_policies_and_artifacts(
        self,
        mock_session: AsyncMock,
        mock_job: MagicMock,
    ) -> None:
        """Handler should process artifacts when policies and artifacts exist."""
        mock_policy = MagicMock()
        mock_policy.expiry_action = RetentionActionType.ARCHIVE

        mock_artifact = EligibleArtifact(
            artifact_type="delivery",
            artifact_ref="del-123",
            created_at=datetime.now(UTC),
            retention_deadline=datetime.now(UTC),
        )

        mock_action_result = RetentionActionResult(
            success=True,
            action_type=RetentionActionType.ARCHIVE,
            archive_ref="archive/delivery/123",
        )

        with (
            patch(
                "qerds.worker.handlers.retention.RetentionPolicyService"
            ) as mock_policy_cls,
            patch(
                "qerds.worker.handlers.retention.RetentionEnforcementService"
            ) as mock_enforcement_cls,
            patch(
                "qerds.worker.handlers.retention.AuditLogService"
            ) as mock_audit_cls,
        ):
            mock_policy_service = AsyncMock()
            mock_policy_service.get_active_policies.return_value = [mock_policy]
            mock_policy_cls.return_value = mock_policy_service

            mock_enforcement_service = AsyncMock()
            mock_enforcement_service.find_eligible_artifacts.return_value = [
                mock_artifact
            ]
            mock_enforcement_service.execute_action.return_value = mock_action_result
            mock_enforcement_cls.return_value = mock_enforcement_service

            mock_audit_service = AsyncMock()
            mock_audit_cls.return_value = mock_audit_service

            result = await enforce_retention_handler(mock_session, mock_job)

        assert result["processed"] == 1
        assert result["archived"] == 1
        assert result["deleted"] == 0
        assert result["policies_evaluated"] == 1
        assert len(result["actions"]) == 1

    @pytest.mark.asyncio
    async def test_handler_batch_size_limit(
        self,
        mock_session: AsyncMock,
        mock_job: MagicMock,
    ) -> None:
        """Handler should respect batch_size limit."""
        mock_job.payload_json = {"batch_size": 1}

        mock_policy = MagicMock()
        mock_policy.expiry_action = RetentionActionType.DELETE

        artifacts = [
            EligibleArtifact(
                artifact_type="content_object",
                artifact_ref=f"co-{i}",
                created_at=datetime.now(UTC),
                retention_deadline=datetime.now(UTC),
            )
            for i in range(5)
        ]

        mock_action_result = RetentionActionResult(
            success=True,
            action_type=RetentionActionType.DELETE,
        )

        with (
            patch(
                "qerds.worker.handlers.retention.RetentionPolicyService"
            ) as mock_policy_cls,
            patch(
                "qerds.worker.handlers.retention.RetentionEnforcementService"
            ) as mock_enforcement_cls,
            patch(
                "qerds.worker.handlers.retention.AuditLogService"
            ) as mock_audit_cls,
        ):
            mock_policy_service = AsyncMock()
            mock_policy_service.get_active_policies.return_value = [mock_policy]
            mock_policy_cls.return_value = mock_policy_service

            mock_enforcement_service = AsyncMock()
            mock_enforcement_service.find_eligible_artifacts.return_value = artifacts
            mock_enforcement_service.execute_action.return_value = mock_action_result
            mock_enforcement_cls.return_value = mock_enforcement_service

            mock_audit_service = AsyncMock()
            mock_audit_cls.return_value = mock_audit_service

            result = await enforce_retention_handler(mock_session, mock_job)

        # Should only process 1 due to batch_size limit
        assert result["processed"] == 1


class TestCreateDefaultCPCEPolicies:
    """Tests for create_default_cpce_policies helper."""

    @pytest.mark.asyncio
    async def test_creates_four_policies(self) -> None:
        """Should create policies for all four artifact types."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        policies = await create_default_cpce_policies(mock_session)

        assert len(policies) == 4

    @pytest.mark.asyncio
    async def test_delivery_policy_meets_cpce_minimum(self) -> None:
        """Delivery policy should have at least 365 days retention."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        policies = await create_default_cpce_policies(mock_session)

        delivery_policies = [
            p for p in policies if p.artifact_type == ArtifactType.DELIVERY.value
        ]
        assert len(delivery_policies) == 1
        assert delivery_policies[0].retention_days >= 365

    @pytest.mark.asyncio
    async def test_evidence_policy_meets_cpce_minimum(self) -> None:
        """Evidence policy should have at least 365 days retention."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        policies = await create_default_cpce_policies(mock_session)

        evidence_policies = [
            p for p in policies if p.artifact_type == ArtifactType.EVIDENCE_OBJECT.value
        ]
        assert len(evidence_policies) == 1
        assert evidence_policies[0].retention_days >= 365


class TestCPCEMinimumRetention:
    """Tests for CPCE minimum retention constant."""

    def test_cpce_minimum_is_365_days(self) -> None:
        """CPCE minimum retention should be exactly 365 days."""
        assert CPCE_MINIMUM_RETENTION_DAYS == 365


class TestRetentionActionType:
    """Tests for RetentionActionType enum from base models."""

    def test_action_type_values(self) -> None:
        """Verify retention action type values."""
        assert RetentionActionType.ARCHIVE.value == "archive"
        assert RetentionActionType.DELETE.value == "delete"
