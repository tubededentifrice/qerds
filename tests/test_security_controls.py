"""Tests for security management controls service.

Tests cover:
- Security policy enumeration and status tracking
- Access control configuration validation
- Security incident tracking and management
- Security event aggregation
- Security report generation
- Audit evidence export
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import AuditLogEntry
from qerds.services.security_controls import (
    DEFAULT_SECURITY_POLICIES,
    ControlAssessment,
    ControlCategory,
    IncidentSeverity,
    IncidentStatus,
    PolicyStatus,
    SecurityControlsService,
    SecurityIncident,
    SecurityPolicy,
    SecurityReport,
    create_security_controls_service,
)
from qerds.services.security_events import SecurityActor, SecurityEventLogger

# =============================================================================
# Enumeration Tests
# =============================================================================


class TestPolicyStatus:
    """Tests for PolicyStatus enumeration."""

    def test_all_statuses_defined(self):
        """All policy status values are defined."""
        statuses = [
            PolicyStatus.ENFORCED,
            PolicyStatus.PARTIALLY_ENFORCED,
            PolicyStatus.NOT_ENFORCED,
            PolicyStatus.NOT_APPLICABLE,
        ]
        assert all(s.value for s in statuses)

    def test_status_values(self):
        """Status values are correct strings."""
        assert PolicyStatus.ENFORCED.value == "enforced"
        assert PolicyStatus.PARTIALLY_ENFORCED.value == "partially_enforced"
        assert PolicyStatus.NOT_ENFORCED.value == "not_enforced"
        assert PolicyStatus.NOT_APPLICABLE.value == "not_applicable"


class TestControlCategory:
    """Tests for ControlCategory enumeration."""

    def test_all_categories_defined(self):
        """All control categories per ETSI EN 319 401/521 are defined."""
        categories = [
            ControlCategory.ACCESS_CONTROL,
            ControlCategory.CRYPTOGRAPHIC,
            ControlCategory.PHYSICAL,
            ControlCategory.OPERATIONAL,
            ControlCategory.COMMUNICATIONS,
            ControlCategory.INCIDENT,
            ControlCategory.CONTINUITY,
            ControlCategory.COMPLIANCE,
        ]
        assert all(c.value for c in categories)

    def test_category_values(self):
        """Category values are correct strings."""
        assert ControlCategory.ACCESS_CONTROL.value == "access_control"
        assert ControlCategory.CRYPTOGRAPHIC.value == "cryptographic"
        assert ControlCategory.INCIDENT.value == "incident"


class TestIncidentSeverity:
    """Tests for IncidentSeverity enumeration."""

    def test_all_severities_defined(self):
        """All incident severity levels are defined."""
        severities = [
            IncidentSeverity.CRITICAL,
            IncidentSeverity.HIGH,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.LOW,
            IncidentSeverity.INFORMATIONAL,
        ]
        assert all(s.value for s in severities)


class TestIncidentStatus:
    """Tests for IncidentStatus enumeration."""

    def test_all_statuses_defined(self):
        """All incident status values are defined."""
        statuses = [
            IncidentStatus.OPEN,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINED,
            IncidentStatus.RESOLVED,
            IncidentStatus.CLOSED,
        ]
        assert all(s.value for s in statuses)


# =============================================================================
# Data Class Tests
# =============================================================================


class TestSecurityPolicy:
    """Tests for SecurityPolicy dataclass."""

    def test_minimal_policy(self):
        """Policy can be created with minimal fields."""
        policy = SecurityPolicy(
            policy_id="POL-001",
            name="Test Policy",
            category=ControlCategory.ACCESS_CONTROL,
            description="Test description",
        )
        assert policy.policy_id == "POL-001"
        assert policy.name == "Test Policy"
        assert policy.category == ControlCategory.ACCESS_CONTROL
        assert policy.status == PolicyStatus.NOT_ENFORCED  # default
        assert policy.requirements == []
        assert policy.exceptions == []

    def test_full_policy(self):
        """Policy can be created with all fields."""
        now = datetime.now(UTC)
        policy = SecurityPolicy(
            policy_id="POL-002",
            name="Full Policy",
            category=ControlCategory.CRYPTOGRAPHIC,
            description="Full description",
            requirements=["REQ-D03", "REQ-D04"],
            status=PolicyStatus.ENFORCED,
            enforcement_method="HSM-backed key storage",
            exceptions=[{"description": "Legacy system", "approved_by": "admin"}],
            last_reviewed=now,
            reviewed_by="admin-123",
        )
        assert policy.status == PolicyStatus.ENFORCED
        assert len(policy.requirements) == 2
        assert len(policy.exceptions) == 1
        assert policy.last_reviewed == now

    def test_policy_to_dict(self):
        """Policy converts to dictionary correctly."""
        now = datetime.now(UTC)
        policy = SecurityPolicy(
            policy_id="POL-003",
            name="Dict Policy",
            category=ControlCategory.OPERATIONAL,
            description="For dict test",
            requirements=["REQ-D08"],
            status=PolicyStatus.PARTIALLY_ENFORCED,
            last_reviewed=now,
            reviewed_by="admin",
        )
        result = policy.to_dict()

        assert result["policy_id"] == "POL-003"
        assert result["category"] == "operational"
        assert result["status"] == "partially_enforced"
        assert result["requirements"] == ["REQ-D08"]
        assert result["last_reviewed"] == now.isoformat()

    def test_policy_is_immutable(self):
        """Policy dataclass is frozen (immutable)."""
        policy = SecurityPolicy(
            policy_id="POL-004",
            name="Immutable",
            category=ControlCategory.COMPLIANCE,
            description="Test immutability",
        )
        with pytest.raises(AttributeError):
            policy.name = "Changed"  # type: ignore


class TestSecurityIncident:
    """Tests for SecurityIncident dataclass."""

    def test_minimal_incident(self):
        """Incident can be created with minimal fields."""
        incident_id = uuid4()
        now = datetime.now(UTC)
        incident = SecurityIncident(
            incident_id=incident_id,
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.OPEN,
            category=ControlCategory.ACCESS_CONTROL,
            detected_at=now,
            detected_by="monitoring",
        )
        assert incident.incident_id == incident_id
        assert incident.severity == IncidentSeverity.MEDIUM
        assert incident.status == IncidentStatus.OPEN
        assert incident.related_events == []
        assert incident.affected_resources == []

    def test_incident_to_dict(self):
        """Incident converts to dictionary correctly."""
        incident_id = uuid4()
        now = datetime.now(UTC)
        incident = SecurityIncident(
            incident_id=incident_id,
            title="Dict Incident",
            description="For dict test",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            category=ControlCategory.INCIDENT,
            detected_at=now,
            detected_by="system",
            related_events=["evt-1", "evt-2"],
            affected_resources=[{"type": "user", "id": "user-123"}],
        )
        result = incident.to_dict()

        assert result["incident_id"] == str(incident_id)
        assert result["severity"] == "high"
        assert result["status"] == "investigating"
        assert result["related_events"] == ["evt-1", "evt-2"]
        assert len(result["affected_resources"]) == 1


class TestControlAssessment:
    """Tests for ControlAssessment dataclass."""

    def test_minimal_assessment(self):
        """Assessment can be created with minimal fields."""
        assessment = ControlAssessment(
            control_id="CTRL-001",
            category=ControlCategory.ACCESS_CONTROL,
            name="Access Control Assessment",
            status=PolicyStatus.ENFORCED,
        )
        assert assessment.control_id == "CTRL-001"
        assert assessment.status == PolicyStatus.ENFORCED
        assert assessment.findings == []

    def test_assessment_to_dict(self):
        """Assessment converts to dictionary correctly."""
        now = datetime.now(UTC)
        next_due = now + timedelta(days=90)
        assessment = ControlAssessment(
            control_id="CTRL-002",
            category=ControlCategory.CRYPTOGRAPHIC,
            name="Crypto Assessment",
            status=PolicyStatus.PARTIALLY_ENFORCED,
            findings=["HSM not certified"],
            evidence_refs=["test_trust.py"],
            assessed_at=now,
            assessed_by="auditor",
            next_assessment_due=next_due,
        )
        result = assessment.to_dict()

        assert result["control_id"] == "CTRL-002"
        assert result["status"] == "partially_enforced"
        assert result["findings"] == ["HSM not certified"]
        assert result["next_assessment_due"] == next_due.isoformat()


class TestSecurityReport:
    """Tests for SecurityReport dataclass."""

    def test_report_to_dict(self):
        """Report converts to dictionary correctly."""
        report_id = uuid4()
        now = datetime.now(UTC)
        report = SecurityReport(
            report_id=report_id,
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_at=now,
            generated_by="admin-123",
            policy_summary={"total": 10, "enforced": 8},
            incident_summary={"total_open": 2},
            event_summary={"total_events": 100},
            control_assessments=[],
            recommendations=["Continue monitoring"],
            report_hash="abc123",
        )
        result = report.to_dict()

        assert result["report_id"] == str(report_id)
        assert result["report_type"] == "daily"
        assert result["policy_summary"]["total"] == 10
        assert result["report_hash"] == "abc123"


# =============================================================================
# Default Policies Tests
# =============================================================================


class TestDefaultSecurityPolicies:
    """Tests for default security policies."""

    def test_default_policies_exist(self):
        """Default policies are defined."""
        assert len(DEFAULT_SECURITY_POLICIES) > 0

    def test_policies_cover_required_categories(self):
        """Default policies cover key ETSI categories."""
        categories = {p.category for p in DEFAULT_SECURITY_POLICIES}

        assert ControlCategory.ACCESS_CONTROL in categories
        assert ControlCategory.CRYPTOGRAPHIC in categories
        assert ControlCategory.OPERATIONAL in categories
        assert ControlCategory.INCIDENT in categories

    def test_policies_reference_requirements(self):
        """Policies reference relevant requirement IDs."""
        all_requirements: set[str] = set()
        for policy in DEFAULT_SECURITY_POLICIES:
            all_requirements.update(policy.requirements)

        # Should reference key REQ-D requirements
        assert "REQ-D01" in all_requirements
        assert "REQ-D02" in all_requirements
        assert "REQ-D03" in all_requirements

    def test_access_control_policies_exist(self):
        """Access control policies are defined."""
        ac_policies = [
            p for p in DEFAULT_SECURITY_POLICIES if p.category == ControlCategory.ACCESS_CONTROL
        ]
        assert len(ac_policies) >= 3  # Strong auth, least privilege, separation of duties

    def test_cryptographic_policies_exist(self):
        """Cryptographic policies are defined."""
        crypto_policies = [
            p for p in DEFAULT_SECURITY_POLICIES if p.category == ControlCategory.CRYPTOGRAPHIC
        ]
        assert len(crypto_policies) >= 2  # State of art crypto, secure key storage


# =============================================================================
# Service Tests - Policy Management
# =============================================================================


class TestSecurityControlsServicePolicies:
    """Tests for SecurityControlsService policy management."""

    @pytest.mark.asyncio
    async def test_get_all_policies(self):
        """get_policy_status returns all policies."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        policies = await service.get_policy_status()

        assert len(policies) == len(DEFAULT_SECURITY_POLICIES)

    @pytest.mark.asyncio
    async def test_get_policies_by_category(self):
        """get_policy_status filters by category."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        ac_policies = await service.get_policy_status(category=ControlCategory.ACCESS_CONTROL)

        assert all(p.category == ControlCategory.ACCESS_CONTROL for p in ac_policies)
        assert len(ac_policies) >= 1

    @pytest.mark.asyncio
    async def test_get_single_policy(self):
        """get_policy returns specific policy."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        policy = await service.get_policy("POL-AC-001")

        assert policy is not None
        assert policy.policy_id == "POL-AC-001"

    @pytest.mark.asyncio
    async def test_get_nonexistent_policy(self):
        """get_policy returns None for missing policy."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        policy = await service.get_policy("POL-NONEXISTENT")

        assert policy is None

    @pytest.mark.asyncio
    async def test_update_policy_status(self):
        """update_policy_status changes policy status."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # Mock the event logger
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_config_change = AsyncMock()

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        updated = await service.update_policy_status(
            policy_id="POL-AC-001",
            status=PolicyStatus.PARTIALLY_ENFORCED,
            actor=actor,
            reason="Testing",
        )

        assert updated.status == PolicyStatus.PARTIALLY_ENFORCED
        assert updated.reviewed_by == "admin-1"
        assert updated.last_reviewed is not None

        # Verify logging occurred
        service._event_logger.log_config_change.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_nonexistent_policy_raises(self):
        """update_policy_status raises for missing policy."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        with pytest.raises(ValueError, match="Policy not found"):
            await service.update_policy_status(
                policy_id="POL-NONEXISTENT",
                status=PolicyStatus.ENFORCED,
                actor=actor,
            )


# =============================================================================
# Service Tests - Access Control Validation
# =============================================================================


class TestSecurityControlsServiceAccessControl:
    """Tests for access control configuration validation."""

    @pytest.mark.asyncio
    async def test_validate_access_control_config(self):
        """validate_access_control_config returns assessment."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        assessment = await service.validate_access_control_config()

        assert assessment.control_id == "CTRL-AC-001"
        assert assessment.category == ControlCategory.ACCESS_CONTROL
        assert assessment.name == "Access Control Configuration"
        assert assessment.status in (PolicyStatus.ENFORCED, PolicyStatus.PARTIALLY_ENFORCED)
        assert assessment.next_assessment_due is not None

    @pytest.mark.asyncio
    async def test_validation_includes_evidence_refs(self):
        """Validation includes references to source code."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        assessment = await service.validate_access_control_config()

        assert len(assessment.evidence_refs) > 0
        assert any("authz" in ref for ref in assessment.evidence_refs)


# =============================================================================
# Service Tests - Incident Management
# =============================================================================


class TestSecurityControlsServiceIncidents:
    """Tests for incident management."""

    @pytest.mark.asyncio
    async def test_report_incident(self):
        """report_incident creates incident record."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # Mock event logger
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        incident = await service.report_incident(
            title="Failed login spike",
            description="Unusual number of failed logins detected",
            severity=IncidentSeverity.MEDIUM,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="monitoring_system",
        )

        assert incident.title == "Failed login spike"
        assert incident.severity == IncidentSeverity.MEDIUM
        assert incident.status == IncidentStatus.OPEN
        assert len(incident.timeline) == 1
        assert incident.timeline[0]["action"] == "incident_reported"

        # Verify logging
        service._event_logger.log_admin_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_report_incident_with_related_events(self):
        """report_incident can include related events."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        incident = await service.report_incident(
            title="Suspicious activity",
            description="Multiple auth failures from same IP",
            severity=IncidentSeverity.HIGH,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="siem",
            related_events=["evt-123", "evt-456"],
            affected_resources=[{"type": "user", "id": "user-789"}],
        )

        assert incident.related_events == ["evt-123", "evt-456"]
        assert len(incident.affected_resources) == 1

    @pytest.mark.asyncio
    async def test_update_incident_status(self):
        """update_incident changes incident status."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        # Create incident first
        incident = await service.report_incident(
            title="Test incident",
            description="For update test",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        updated = await service.update_incident(
            incident_id=incident.incident_id,
            status=IncidentStatus.INVESTIGATING,
            actor=actor,
        )

        assert updated.status == IncidentStatus.INVESTIGATING

    @pytest.mark.asyncio
    async def test_update_incident_with_resolution(self):
        """update_incident can set resolution."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        incident = await service.report_incident(
            title="Resolved incident",
            description="Will be resolved",
            severity=IncidentSeverity.INFORMATIONAL,
            category=ControlCategory.COMPLIANCE,
            detected_by="test",
        )

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        updated = await service.update_incident(
            incident_id=incident.incident_id,
            status=IncidentStatus.RESOLVED,
            resolution={"root_cause": "Configuration error", "fix": "Updated config"},
            actor=actor,
        )

        assert updated.status == IncidentStatus.RESOLVED
        assert updated.resolution is not None
        assert updated.resolution["root_cause"] == "Configuration error"

    @pytest.mark.asyncio
    async def test_update_nonexistent_incident_raises(self):
        """update_incident raises for missing incident."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")

        with pytest.raises(ValueError, match="Incident not found"):
            await service.update_incident(
                incident_id=uuid4(),
                status=IncidentStatus.CLOSED,
                actor=actor,
            )

    @pytest.mark.asyncio
    async def test_get_incident(self):
        """get_incident returns incident by ID."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        created = await service.report_incident(
            title="Get test",
            description="For get test",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        retrieved = await service.get_incident(created.incident_id)

        assert retrieved is not None
        assert retrieved.incident_id == created.incident_id

    @pytest.mark.asyncio
    async def test_get_nonexistent_incident(self):
        """get_incident returns None for missing incident."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        result = await service.get_incident(uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_get_incidents_all(self):
        """get_incidents returns all incidents."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        # Create multiple incidents
        for i in range(3):
            await service.report_incident(
                title=f"Incident {i}",
                description=f"Description {i}",
                severity=IncidentSeverity.LOW,
                category=ControlCategory.OPERATIONAL,
                detected_by="test",
            )

        incidents = await service.get_incidents()

        assert len(incidents) == 3

    @pytest.mark.asyncio
    async def test_get_incidents_by_status(self):
        """get_incidents filters by status."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        # Create incidents with different statuses
        incident = await service.report_incident(
            title="Open incident",
            description="Will stay open",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        actor = SecurityActor(actor_id="admin-1", actor_type="admin")
        await service.update_incident(
            incident_id=incident.incident_id,
            status=IncidentStatus.RESOLVED,
            actor=actor,
        )

        await service.report_incident(
            title="Another open",
            description="Also open",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        open_incidents = await service.get_incidents(status=IncidentStatus.OPEN)
        resolved_incidents = await service.get_incidents(status=IncidentStatus.RESOLVED)

        assert len(open_incidents) == 1
        assert len(resolved_incidents) == 1

    @pytest.mark.asyncio
    async def test_get_incidents_by_severity(self):
        """get_incidents filters by severity."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        await service.report_incident(
            title="High severity",
            description="Critical issue",
            severity=IncidentSeverity.HIGH,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="test",
        )

        await service.report_incident(
            title="Low severity",
            description="Minor issue",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        high_incidents = await service.get_incidents(severity=IncidentSeverity.HIGH)

        assert len(high_incidents) == 1
        assert high_incidents[0].severity == IncidentSeverity.HIGH

    @pytest.mark.asyncio
    async def test_get_open_incidents_count(self):
        """get_open_incidents_count returns counts by severity."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_admin_action = AsyncMock()

        await service.report_incident(
            title="Critical",
            description="Critical issue",
            severity=IncidentSeverity.CRITICAL,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="test",
        )

        await service.report_incident(
            title="High",
            description="High issue",
            severity=IncidentSeverity.HIGH,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="test",
        )

        await service.report_incident(
            title="Low",
            description="Low issue",
            severity=IncidentSeverity.LOW,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        counts = await service.get_open_incidents_count()

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["low"] == 1
        assert counts["medium"] == 0


# =============================================================================
# Service Tests - Event Aggregation
# =============================================================================


class TestSecurityControlsServiceEventAggregation:
    """Tests for security event aggregation."""

    @pytest.mark.asyncio
    async def test_get_event_summary(self):
        """get_event_summary aggregates events."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # Mock event logger with sample events
        mock_events = [
            create_mock_audit_entry(event_type="auth_login"),
            create_mock_audit_entry(event_type="auth_login"),
            create_mock_audit_entry(event_type="auth_failed"),
            create_mock_audit_entry(event_type="authz_denied"),
            create_mock_audit_entry(event_type="admin_action"),
        ]
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=mock_events)

        now = datetime.now(UTC)
        summary = await service.get_event_summary(
            period_start=now - timedelta(days=1),
            period_end=now,
        )

        assert summary["total_events"] == 5
        assert summary["auth_success"] == 2
        assert summary["auth_failure"] == 1
        assert summary["authz_denied"] == 1
        assert summary["admin_actions"] == 1
        assert "failure_ratio" in summary

    @pytest.mark.asyncio
    async def test_get_event_summary_calculates_failure_ratio(self):
        """get_event_summary calculates authentication failure ratio."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # 3 successes, 2 failures = 40% failure rate
        mock_events = [
            create_mock_audit_entry(event_type="auth_login"),
            create_mock_audit_entry(event_type="auth_login"),
            create_mock_audit_entry(event_type="auth_login"),
            create_mock_audit_entry(event_type="auth_failed"),
            create_mock_audit_entry(event_type="auth_failed"),
        ]
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=mock_events)

        now = datetime.now(UTC)
        summary = await service.get_event_summary(
            period_start=now - timedelta(days=1),
            period_end=now,
        )

        assert summary["failure_ratio"] == pytest.approx(0.4)

    @pytest.mark.asyncio
    async def test_get_event_summary_handles_no_auth_events(self):
        """get_event_summary handles zero auth events gracefully."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        mock_events = [
            create_mock_audit_entry(event_type="config_changed"),
        ]
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=mock_events)

        now = datetime.now(UTC)
        summary = await service.get_event_summary(
            period_start=now - timedelta(days=1),
            period_end=now,
        )

        assert summary["failure_ratio"] == 0.0


# =============================================================================
# Service Tests - Report Generation
# =============================================================================


class TestSecurityControlsServiceReports:
    """Tests for security report generation."""

    @pytest.mark.asyncio
    async def test_generate_security_report(self):
        """generate_security_report creates comprehensive report."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # Mock dependencies
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_sensitive_access = AsyncMock()

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin-123",
        )

        assert report.report_type == "daily"
        assert report.generated_by == "admin-123"
        assert report.report_hash  # Should have hash
        assert "total" in report.policy_summary
        assert "total_open" in report.incident_summary
        assert "total_events" in report.event_summary
        assert len(report.recommendations) > 0

    @pytest.mark.asyncio
    async def test_report_includes_policy_summary(self):
        """Report includes policy status summary."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_sensitive_access = AsyncMock()

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="weekly",
            period_start=now - timedelta(days=7),
            period_end=now,
            generated_by="admin",
        )

        summary = report.policy_summary
        assert "total" in summary
        assert "enforced" in summary
        assert "partially_enforced" in summary
        assert "by_category" in summary

    @pytest.mark.asyncio
    async def test_report_includes_incident_summary(self):
        """Report includes incident summary."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_admin_action = AsyncMock()
        service._event_logger.log_sensitive_access = AsyncMock()

        # Create an incident
        await service.report_incident(
            title="Test incident",
            description="For report test",
            severity=IncidentSeverity.MEDIUM,
            category=ControlCategory.OPERATIONAL,
            detected_by="test",
        )

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin",
        )

        summary = report.incident_summary
        assert summary["total_open"] >= 1

    @pytest.mark.asyncio
    async def test_report_generates_recommendations(self):
        """Report generates relevant recommendations."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_admin_action = AsyncMock()
        service._event_logger.log_sensitive_access = AsyncMock()

        # Create critical incident to trigger recommendation
        await service.report_incident(
            title="Critical incident",
            description="Urgent",
            severity=IncidentSeverity.CRITICAL,
            category=ControlCategory.ACCESS_CONTROL,
            detected_by="test",
        )

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin",
        )

        # Should recommend addressing critical incidents
        assert any("critical" in r.lower() for r in report.recommendations)

    @pytest.mark.asyncio
    async def test_report_logs_generation(self):
        """Report generation is logged."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_sensitive_access = AsyncMock()

        now = datetime.now(UTC)
        await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin",
        )

        service._event_logger.log_sensitive_access.assert_called_once()
        call_kwargs = service._event_logger.log_sensitive_access.call_args.kwargs
        assert call_kwargs["resource_type"] == "security_report"
        assert call_kwargs["access_type"] == "generate"


# =============================================================================
# Service Tests - Audit Evidence Export
# =============================================================================


class TestSecurityControlsServiceExport:
    """Tests for audit evidence export."""

    @pytest.mark.asyncio
    async def test_export_audit_evidence(self):
        """export_audit_evidence creates evidence package."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.export_events = AsyncMock(
            return_value={
                "stream": "security",
                "record_count": 10,
                "events": [],
                "verification": {"valid": True},
            }
        )
        service._event_logger.log_sensitive_access = AsyncMock()

        today = datetime.now(UTC).date()
        evidence = await service.export_audit_evidence(
            start_date=today - timedelta(days=30),
            end_date=today,
            include_policies=True,
            include_incidents=True,
            include_events=True,
            exported_by="auditor-1",
        )

        assert "export_id" in evidence
        assert "exported_at" in evidence
        assert "policies" in evidence
        assert "incidents" in evidence
        assert "security_events" in evidence
        assert "evidence_hash" in evidence

    @pytest.mark.asyncio
    async def test_export_without_optional_sections(self):
        """export_audit_evidence can exclude sections."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_sensitive_access = AsyncMock()

        today = datetime.now(UTC).date()
        evidence = await service.export_audit_evidence(
            start_date=today - timedelta(days=30),
            end_date=today,
            include_policies=False,
            include_incidents=False,
            include_events=False,
            exported_by="auditor-1",
        )

        assert "policies" not in evidence
        assert "incidents" not in evidence
        assert "security_events" not in evidence
        assert "export_id" in evidence  # Metadata always included

    @pytest.mark.asyncio
    async def test_export_logs_access(self):
        """Export is logged as sensitive access."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.log_sensitive_access = AsyncMock()

        today = datetime.now(UTC).date()
        await service.export_audit_evidence(
            start_date=today - timedelta(days=30),
            end_date=today,
            include_policies=False,
            include_incidents=False,
            include_events=False,
            exported_by="auditor-1",
        )

        service._event_logger.log_sensitive_access.assert_called_once()
        call_kwargs = service._event_logger.log_sensitive_access.call_args.kwargs
        assert call_kwargs["resource_type"] == "security_audit_evidence"
        assert call_kwargs["access_type"] == "export"


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestFactoryFunction:
    """Tests for factory function."""

    @pytest.mark.asyncio
    async def test_create_security_controls_service(self):
        """Factory creates service instance."""
        session = AsyncMock()

        service = await create_security_controls_service(session)

        assert isinstance(service, SecurityControlsService)


# =============================================================================
# Recommendation Generation Tests
# =============================================================================


class TestRecommendationGeneration:
    """Tests for recommendation generation logic."""

    @pytest.mark.asyncio
    async def test_recommends_for_not_enforced_policies(self):
        """Generates recommendation for not-enforced policies."""
        session = AsyncMock()
        service = SecurityControlsService(session)
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=[])
        service._event_logger.log_config_change = AsyncMock()
        service._event_logger.log_sensitive_access = AsyncMock()

        # Set a policy to not enforced
        actor = SecurityActor(actor_id="admin", actor_type="admin")
        await service.update_policy_status(
            policy_id="POL-OP-002",
            status=PolicyStatus.NOT_ENFORCED,
            actor=actor,
        )

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin",
        )

        # Should have recommendation about not-enforced policies
        assert any("POL-OP-002" in r for r in report.recommendations)

    @pytest.mark.asyncio
    async def test_recommends_for_high_failure_ratio(self):
        """Generates recommendation for high auth failure ratio."""
        session = AsyncMock()
        service = SecurityControlsService(session)

        # Mock high failure ratio events (15% failure)
        mock_events = [
            *[create_mock_audit_entry(event_type="auth_login") for _ in range(85)],
            *[create_mock_audit_entry(event_type="auth_failed") for _ in range(15)],
        ]
        service._event_logger = AsyncMock(spec=SecurityEventLogger)
        service._event_logger.get_events = AsyncMock(return_value=mock_events)
        service._event_logger.log_sensitive_access = AsyncMock()

        now = datetime.now(UTC)
        report = await service.generate_security_report(
            report_type="daily",
            period_start=now - timedelta(days=1),
            period_end=now,
            generated_by="admin",
        )

        # Should have recommendation about auth failures
        has_auth_rec = any(
            "authentication" in r.lower() or "failure" in r.lower() for r in report.recommendations
        )
        assert has_auth_rec


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
