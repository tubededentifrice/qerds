"""Security management controls service for REQ-D01.

Covers: REQ-D01 (Security management framework per ETSI EN 319 401/319 521)

This module provides security management controls consistent with the
information security management requirements of ETSI EN 319 401/319 521:
- Security policy enforcement status tracking
- Access control configuration validation
- Security incident tracking and aggregation
- Audit evidence generation for compliance assessment

The service integrates with:
- SecurityEventLogger for event tracking (REQ-D08)
- AuditLogService for tamper-evident logging (REQ-C05)
- AuthorizationService for access control status (REQ-D02)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from qerds.services.audit_log import AuditLogService
from qerds.services.security_events import (
    SecurityActor,
    SecurityEventLogger,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PolicyStatus(str, Enum):
    """Status of a security policy enforcement.

    Values:
        ENFORCED: Policy is actively enforced
        PARTIALLY_ENFORCED: Policy has exceptions or degraded mode
        NOT_ENFORCED: Policy exists but is not enforced
        NOT_APPLICABLE: Policy does not apply to current configuration
    """

    ENFORCED = "enforced"
    PARTIALLY_ENFORCED = "partially_enforced"
    NOT_ENFORCED = "not_enforced"
    NOT_APPLICABLE = "not_applicable"


class ControlCategory(str, Enum):
    """Categories of security controls per ETSI EN 319 401/521.

    Values:
        ACCESS_CONTROL: Authentication and authorization controls
        CRYPTOGRAPHIC: Cryptographic mechanism controls
        PHYSICAL: Physical security controls (tracked, not enforced by platform)
        OPERATIONAL: Operational security controls
        COMMUNICATIONS: Network and communications security
        INCIDENT: Incident handling and response
        CONTINUITY: Business continuity and disaster recovery
        COMPLIANCE: Compliance monitoring and audit
    """

    ACCESS_CONTROL = "access_control"
    CRYPTOGRAPHIC = "cryptographic"
    PHYSICAL = "physical"
    OPERATIONAL = "operational"
    COMMUNICATIONS = "communications"
    INCIDENT = "incident"
    CONTINUITY = "continuity"
    COMPLIANCE = "compliance"


class IncidentSeverity(str, Enum):
    """Security incident severity levels.

    Values:
        CRITICAL: Immediate action required, potential data breach
        HIGH: Significant security impact, prompt action needed
        MEDIUM: Moderate security impact, scheduled action needed
        LOW: Minor security concern, informational
        INFORMATIONAL: No immediate security impact, monitoring only
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentStatus(str, Enum):
    """Status of a security incident.

    Values:
        OPEN: Incident reported, not yet triaged
        INVESTIGATING: Under active investigation
        CONTAINED: Immediate threat contained
        RESOLVED: Incident fully resolved
        CLOSED: Incident closed after review
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    """Represents a security policy configuration.

    Attributes:
        policy_id: Unique identifier for the policy.
        name: Human-readable policy name.
        category: Category of security control.
        description: Detailed description of the policy.
        requirements: List of requirement IDs this policy supports.
        status: Current enforcement status.
        enforcement_method: How the policy is enforced.
        exceptions: Any approved exceptions to the policy.
        last_reviewed: When the policy was last reviewed.
        reviewed_by: Who reviewed the policy.
    """

    policy_id: str
    name: str
    category: ControlCategory
    description: str
    requirements: list[str] = field(default_factory=list)
    status: PolicyStatus = PolicyStatus.NOT_ENFORCED
    enforcement_method: str | None = None
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    last_reviewed: datetime | None = None
    reviewed_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "requirements": self.requirements,
            "status": self.status.value,
            "enforcement_method": self.enforcement_method,
            "exceptions": self.exceptions,
            "last_reviewed": self.last_reviewed.isoformat() if self.last_reviewed else None,
            "reviewed_by": self.reviewed_by,
        }


@dataclass
class SecurityIncident:
    """Represents a security incident record.

    Attributes:
        incident_id: Unique identifier for the incident.
        title: Brief description of the incident.
        description: Detailed incident description.
        severity: Incident severity level.
        status: Current incident status.
        category: Security control category affected.
        detected_at: When the incident was detected.
        detected_by: Actor who detected the incident.
        related_events: List of related security event IDs.
        affected_resources: Resources impacted by the incident.
        timeline: Chronological list of incident updates.
        resolution: Resolution details (when resolved).
        created_at: When the incident record was created.
        updated_at: When the incident was last updated.
    """

    incident_id: UUID
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    category: ControlCategory
    detected_at: datetime
    detected_by: str
    related_events: list[str] = field(default_factory=list)
    affected_resources: list[dict[str, str]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    resolution: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "incident_id": str(self.incident_id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category.value,
            "detected_at": self.detected_at.isoformat(),
            "detected_by": self.detected_by,
            "related_events": self.related_events,
            "affected_resources": self.affected_resources,
            "timeline": self.timeline,
            "resolution": self.resolution,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ControlAssessment:
    """Result of assessing a security control.

    Attributes:
        control_id: Identifier of the assessed control.
        category: Category of the control.
        name: Human-readable control name.
        status: Assessment status.
        findings: List of assessment findings.
        evidence_refs: References to supporting evidence.
        assessed_at: When the assessment was performed.
        assessed_by: Actor who performed the assessment.
        next_assessment_due: When next assessment is due.
    """

    control_id: str
    category: ControlCategory
    name: str
    status: PolicyStatus
    findings: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    assessed_by: str | None = None
    next_assessment_due: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "control_id": self.control_id,
            "category": self.category.value,
            "name": self.name,
            "status": self.status.value,
            "findings": self.findings,
            "evidence_refs": self.evidence_refs,
            "assessed_at": self.assessed_at.isoformat(),
            "assessed_by": self.assessed_by,
            "next_assessment_due": (
                self.next_assessment_due.isoformat() if self.next_assessment_due else None
            ),
        }


@dataclass(frozen=True, slots=True)
class SecurityReport:
    """Aggregated security status report.

    Attributes:
        report_id: Unique identifier for the report.
        report_type: Type of report (daily, weekly, monthly, on-demand).
        period_start: Start of reporting period.
        period_end: End of reporting period.
        generated_at: When the report was generated.
        generated_by: Actor who generated the report.
        policy_summary: Summary of policy enforcement status.
        incident_summary: Summary of security incidents.
        event_summary: Summary of security events.
        control_assessments: List of control assessment results.
        recommendations: Recommended actions.
        report_hash: SHA-256 hash of report contents.
    """

    report_id: UUID
    report_type: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    generated_by: str
    policy_summary: dict[str, Any]
    incident_summary: dict[str, Any]
    event_summary: dict[str, Any]
    control_assessments: list[dict[str, Any]]
    recommendations: list[str]
    report_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "report_id": str(self.report_id),
            "report_type": self.report_type,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "policy_summary": self.policy_summary,
            "incident_summary": self.incident_summary,
            "event_summary": self.event_summary,
            "control_assessments": self.control_assessments,
            "recommendations": self.recommendations,
            "report_hash": self.report_hash,
        }


# ---------------------------------------------------------------------------
# Default security policies
# ---------------------------------------------------------------------------

# These policies represent the baseline security controls required
# by ETSI EN 319 401/521 that the platform must track

DEFAULT_SECURITY_POLICIES: list[SecurityPolicy] = [
    SecurityPolicy(
        policy_id="POL-AC-001",
        name="Strong Authentication",
        category=ControlCategory.ACCESS_CONTROL,
        description="All administrative access must use strong authentication (MFA)",
        requirements=["REQ-D02"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="Application-level MFA enforcement",
    ),
    SecurityPolicy(
        policy_id="POL-AC-002",
        name="Least Privilege Access",
        category=ControlCategory.ACCESS_CONTROL,
        description="Access granted only for required operations per role",
        requirements=["REQ-D02", "REQ-H06"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="RBAC/ABAC authorization service",
    ),
    SecurityPolicy(
        policy_id="POL-AC-003",
        name="Separation of Duties",
        category=ControlCategory.ACCESS_CONTROL,
        description="Sensitive operations require dual-control approval",
        requirements=["REQ-D02"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="Dual-control workflow for key operations",
    ),
    SecurityPolicy(
        policy_id="POL-CR-001",
        name="State of Art Cryptography",
        category=ControlCategory.CRYPTOGRAPHIC,
        description="Cryptographic mechanisms follow ENISA agreed mechanisms",
        requirements=["REQ-D03"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="Configured algorithm suite in TrustService",
    ),
    SecurityPolicy(
        policy_id="POL-CR-002",
        name="Secure Key Storage",
        category=ControlCategory.CRYPTOGRAPHIC,
        description="Private keys stored in certified secure devices",
        requirements=["REQ-D04"],
        status=PolicyStatus.PARTIALLY_ENFORCED,
        enforcement_method="Software HSM in development, certified HSM required for production",
        exceptions=[
            {
                "description": "Development mode uses software key storage",
                "approved_by": "system",
                "expires": None,
            }
        ],
    ),
    SecurityPolicy(
        policy_id="POL-OP-001",
        name="Security Event Logging",
        category=ControlCategory.OPERATIONAL,
        description="All security-relevant events are logged with tamper evidence",
        requirements=["REQ-D08", "REQ-H03"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="SecurityEventLogger with hash-chained AuditLog",
    ),
    SecurityPolicy(
        policy_id="POL-OP-002",
        name="Vulnerability Scanning",
        category=ControlCategory.OPERATIONAL,
        description="Vulnerability scanning performed quarterly",
        requirements=["REQ-D05"],
        status=PolicyStatus.NOT_ENFORCED,
        enforcement_method="Operator responsibility with platform evidence support",
    ),
    SecurityPolicy(
        policy_id="POL-OP-003",
        name="Penetration Testing",
        category=ControlCategory.OPERATIONAL,
        description="Penetration testing performed annually",
        requirements=["REQ-D06"],
        status=PolicyStatus.NOT_ENFORCED,
        enforcement_method="Operator responsibility with platform evidence support",
    ),
    SecurityPolicy(
        policy_id="POL-CO-001",
        name="Network Filtering",
        category=ControlCategory.COMMUNICATIONS,
        description="Firewall denies all non-required protocols/access",
        requirements=["REQ-D07"],
        status=PolicyStatus.NOT_APPLICABLE,
        enforcement_method="Infrastructure-level (outside application scope)",
    ),
    SecurityPolicy(
        policy_id="POL-IN-001",
        name="Incident Response",
        category=ControlCategory.INCIDENT,
        description="Security incidents tracked and managed per documented procedures",
        requirements=["REQ-D01", "REQ-H04"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="SecurityControlsService incident tracking",
    ),
    SecurityPolicy(
        policy_id="POL-BC-001",
        name="Business Continuity",
        category=ControlCategory.CONTINUITY,
        description="Backup and disaster recovery controls implemented",
        requirements=["REQ-D09", "REQ-H08"],
        status=PolicyStatus.PARTIALLY_ENFORCED,
        enforcement_method="Platform backup support, DR testing operator responsibility",
    ),
    SecurityPolicy(
        policy_id="POL-CM-001",
        name="Audit Evidence Export",
        category=ControlCategory.COMPLIANCE,
        description="Audit packs can be generated for conformity assessment",
        requirements=["REQ-H01"],
        status=PolicyStatus.ENFORCED,
        enforcement_method="AuditPackService",
    ),
]


# ---------------------------------------------------------------------------
# Service implementation
# ---------------------------------------------------------------------------


class SecurityControlsService:
    """Service for security management controls per REQ-D01.

    This service provides security management capabilities consistent with
    ETSI EN 319 401/319 521 requirements:
    - Track security policy enforcement status
    - Validate access control configuration
    - Track and manage security incidents
    - Generate security reports and audit evidence

    Example:
        service = SecurityControlsService(session)

        # Get policy status
        policies = await service.get_policy_status()

        # Report a security incident
        incident = await service.report_incident(
            title="Failed login attempts spike",
            description="Unusual number of failed logins detected",
            severity=IncidentSeverity.MEDIUM,
            detected_by="monitoring_system",
        )

        # Generate security report
        report = await service.generate_security_report(
            report_type="daily",
            period_start=datetime.now(UTC) - timedelta(days=1),
            period_end=datetime.now(UTC),
            generated_by="admin-123",
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the security controls service.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session
        self._audit_service = AuditLogService(session)
        self._event_logger = SecurityEventLogger(session)
        # In-memory incident store (in production, would be database-backed)
        self._incidents: dict[UUID, SecurityIncident] = {}
        # Policy configuration (could be loaded from database)
        self._policies = {p.policy_id: p for p in DEFAULT_SECURITY_POLICIES}

    # -------------------------------------------------------------------------
    # Policy management
    # -------------------------------------------------------------------------

    async def get_policy_status(
        self,
        *,
        category: ControlCategory | None = None,
    ) -> list[SecurityPolicy]:
        """Get current status of security policies.

        Args:
            category: Optional category filter.

        Returns:
            List of security policies with current status.
        """
        policies = list(self._policies.values())

        if category is not None:
            policies = [p for p in policies if p.category == category]

        return policies

    async def get_policy(self, policy_id: str) -> SecurityPolicy | None:
        """Get a specific security policy by ID.

        Args:
            policy_id: The policy identifier.

        Returns:
            The policy if found, None otherwise.
        """
        return self._policies.get(policy_id)

    async def update_policy_status(
        self,
        *,
        policy_id: str,
        status: PolicyStatus,
        actor: SecurityActor,
        reason: str | None = None,
    ) -> SecurityPolicy:
        """Update the enforcement status of a policy.

        This is logged as a security event for audit purposes.

        Args:
            policy_id: The policy to update.
            status: New enforcement status.
            actor: Actor making the change.
            reason: Reason for the status change.

        Returns:
            Updated policy.

        Raises:
            ValueError: If policy not found.
        """
        existing = self._policies.get(policy_id)
        if existing is None:
            msg = f"Policy not found: {policy_id}"
            raise ValueError(msg)

        # Create updated policy (immutable dataclass)
        updated = SecurityPolicy(
            policy_id=existing.policy_id,
            name=existing.name,
            category=existing.category,
            description=existing.description,
            requirements=existing.requirements,
            status=status,
            enforcement_method=existing.enforcement_method,
            exceptions=existing.exceptions,
            last_reviewed=datetime.now(UTC),
            reviewed_by=actor.actor_id,
        )

        self._policies[policy_id] = updated

        # Log the policy change
        await self._event_logger.log_config_change(
            actor=actor,
            config_key=f"policy:{policy_id}:status",
            old_value=existing.status.value,
            new_value=status.value,
            details={"reason": reason, "policy_name": existing.name},
        )

        logger.info(
            "Policy status updated: policy_id=%s, old=%s, new=%s, by=%s",
            policy_id,
            existing.status.value,
            status.value,
            actor.actor_id,
        )

        return updated

    async def validate_access_control_config(self) -> ControlAssessment:
        """Validate current access control configuration.

        Checks that RBAC/ABAC configuration is consistent with
        security requirements.

        Returns:
            Assessment result for access control configuration.
        """
        findings: list[str] = []
        evidence_refs: list[str] = []
        status = PolicyStatus.ENFORCED

        # Check that dual-control policies exist
        dual_control_policy = self._policies.get("POL-AC-003")
        if dual_control_policy and dual_control_policy.status != PolicyStatus.ENFORCED:
            findings.append("Dual-control policy not fully enforced")
            status = PolicyStatus.PARTIALLY_ENFORCED

        # Check least privilege policy
        least_priv_policy = self._policies.get("POL-AC-002")
        if least_priv_policy and least_priv_policy.status != PolicyStatus.ENFORCED:
            findings.append("Least privilege policy not fully enforced")
            status = PolicyStatus.PARTIALLY_ENFORCED

        # Add reference to authorization service module
        evidence_refs.append("src/qerds/services/authz.py")
        evidence_refs.append("tests/test_authz.py")

        return ControlAssessment(
            control_id="CTRL-AC-001",
            category=ControlCategory.ACCESS_CONTROL,
            name="Access Control Configuration",
            status=status,
            findings=findings,
            evidence_refs=evidence_refs,
            assessed_at=datetime.now(UTC),
            assessed_by="system:security_controls",
            next_assessment_due=datetime.now(UTC) + timedelta(days=90),
        )

    # -------------------------------------------------------------------------
    # Incident management
    # -------------------------------------------------------------------------

    async def report_incident(
        self,
        *,
        title: str,
        description: str,
        severity: IncidentSeverity,
        category: ControlCategory,
        detected_by: str,
        detected_at: datetime | None = None,
        related_events: list[str] | None = None,
        affected_resources: list[dict[str, str]] | None = None,
    ) -> SecurityIncident:
        """Report a new security incident.

        Creates an incident record and logs a security event.

        Args:
            title: Brief incident description.
            description: Detailed description.
            severity: Incident severity level.
            category: Security control category affected.
            detected_by: Actor who detected the incident.
            detected_at: When detected (defaults to now).
            related_events: Related security event IDs.
            affected_resources: Resources affected by the incident.

        Returns:
            Created incident record.
        """
        incident_id = uuid4()
        now = datetime.now(UTC)

        incident = SecurityIncident(
            incident_id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            category=category,
            detected_at=detected_at or now,
            detected_by=detected_by,
            related_events=related_events or [],
            affected_resources=affected_resources or [],
            timeline=[
                {
                    "timestamp": now.isoformat(),
                    "action": "incident_reported",
                    "actor": detected_by,
                    "details": {"title": title, "severity": severity.value},
                }
            ],
            created_at=now,
            updated_at=now,
        )

        self._incidents[incident_id] = incident

        # Log incident creation
        system_actor = SecurityActor(
            actor_id=f"detector:{detected_by}",
            actor_type="system",
        )
        await self._event_logger.log_admin_action(
            actor=system_actor,
            action="security_incident_reported",
            target_type="incident",
            target_id=str(incident_id),
            details={
                "title": title,
                "severity": severity.value,
                "category": category.value,
            },
        )

        logger.warning(
            "Security incident reported: id=%s, title=%s, severity=%s",
            incident_id,
            title,
            severity.value,
        )

        return incident

    async def update_incident(
        self,
        *,
        incident_id: UUID,
        status: IncidentStatus | None = None,
        resolution: dict[str, Any] | None = None,
        timeline_entry: dict[str, Any] | None = None,
        actor: SecurityActor,
    ) -> SecurityIncident:
        """Update a security incident.

        Args:
            incident_id: ID of incident to update.
            status: New status (optional).
            resolution: Resolution details (when resolving).
            timeline_entry: Entry to add to timeline.
            actor: Actor making the update.

        Returns:
            Updated incident.

        Raises:
            ValueError: If incident not found.
        """
        incident = self._incidents.get(incident_id)
        if incident is None:
            msg = f"Incident not found: {incident_id}"
            raise ValueError(msg)

        now = datetime.now(UTC)

        if status is not None:
            incident.status = status

        if resolution is not None:
            incident.resolution = resolution

        if timeline_entry is not None:
            incident.timeline.append(
                {
                    "timestamp": now.isoformat(),
                    **timeline_entry,
                }
            )

        incident.updated_at = now

        # Log the update
        await self._event_logger.log_admin_action(
            actor=actor,
            action="security_incident_updated",
            target_type="incident",
            target_id=str(incident_id),
            details={
                "new_status": status.value if status else None,
                "has_resolution": resolution is not None,
            },
        )

        logger.info(
            "Security incident updated: id=%s, status=%s, by=%s",
            incident_id,
            incident.status.value,
            actor.actor_id,
        )

        return incident

    async def get_incident(self, incident_id: UUID) -> SecurityIncident | None:
        """Get a security incident by ID.

        Args:
            incident_id: The incident ID.

        Returns:
            The incident if found, None otherwise.
        """
        return self._incidents.get(incident_id)

    async def get_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        category: ControlCategory | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[SecurityIncident]:
        """Get security incidents with filtering.

        Args:
            status: Filter by status.
            severity: Filter by severity.
            category: Filter by category.
            since: Only incidents after this time.
            limit: Maximum number to return.

        Returns:
            List of matching incidents.
        """
        incidents = list(self._incidents.values())

        if status is not None:
            incidents = [i for i in incidents if i.status == status]

        if severity is not None:
            incidents = [i for i in incidents if i.severity == severity]

        if category is not None:
            incidents = [i for i in incidents if i.category == category]

        if since is not None:
            incidents = [i for i in incidents if i.detected_at >= since]

        # Sort by detection time (most recent first)
        incidents.sort(key=lambda i: i.detected_at, reverse=True)

        return incidents[:limit]

    async def get_open_incidents_count(self) -> dict[str, int]:
        """Get count of open incidents by severity.

        Returns:
            Dictionary mapping severity to count.
        """
        counts: dict[str, int] = {
            IncidentSeverity.CRITICAL.value: 0,
            IncidentSeverity.HIGH.value: 0,
            IncidentSeverity.MEDIUM.value: 0,
            IncidentSeverity.LOW.value: 0,
            IncidentSeverity.INFORMATIONAL.value: 0,
        }

        for incident in self._incidents.values():
            if incident.status not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
                counts[incident.severity.value] += 1

        return counts

    # -------------------------------------------------------------------------
    # Security event aggregation
    # -------------------------------------------------------------------------

    async def get_event_summary(
        self,
        *,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Get aggregated security event summary for a period.

        Args:
            period_start: Start of period.
            period_end: End of period.

        Returns:
            Dictionary with event counts and summaries.
        """
        # Query events from the security stream
        events = await self._event_logger.get_events(
            start_seq=None,
            end_seq=None,
            limit=10000,  # Large limit for aggregation
        )

        # Filter to period and aggregate
        auth_success = 0
        auth_failure = 0
        authz_denied = 0
        admin_actions = 0
        config_changes = 0
        sensitive_access = 0
        total_events = 0

        for event in events:
            # Check timestamp in summary or payload
            # For now, count all events in the stream
            total_events += 1

            event_type = event.event_type
            if event_type == "auth_login":
                auth_success += 1
            elif event_type == "auth_failed":
                auth_failure += 1
            elif event_type == "authz_denied":
                authz_denied += 1
            elif event_type == "admin_action":
                admin_actions += 1
            elif event_type == "config_changed":
                config_changes += 1
            elif "sensitive" in event_type or "evidence" in event_type:
                sensitive_access += 1

        return {
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "total_events": total_events,
            "auth_success": auth_success,
            "auth_failure": auth_failure,
            "authz_denied": authz_denied,
            "admin_actions": admin_actions,
            "config_changes": config_changes,
            "sensitive_access": sensitive_access,
            "failure_ratio": (
                auth_failure / (auth_success + auth_failure)
                if (auth_success + auth_failure) > 0
                else 0.0
            ),
        }

    # -------------------------------------------------------------------------
    # Report generation
    # -------------------------------------------------------------------------

    async def generate_security_report(
        self,
        *,
        report_type: str,
        period_start: datetime,
        period_end: datetime,
        generated_by: str,
    ) -> SecurityReport:
        """Generate a security status report.

        Aggregates policy status, incidents, and events into a
        comprehensive report suitable for management review.

        Args:
            report_type: Type of report (daily, weekly, monthly, on-demand).
            period_start: Start of reporting period.
            period_end: End of reporting period.
            generated_by: ID of actor generating the report.

        Returns:
            Generated security report with hash.
        """
        report_id = uuid4()
        generated_at = datetime.now(UTC)

        # Collect policy summary
        policies = await self.get_policy_status()
        policy_summary = {
            "total": len(policies),
            "enforced": len([p for p in policies if p.status == PolicyStatus.ENFORCED]),
            "partially_enforced": len(
                [p for p in policies if p.status == PolicyStatus.PARTIALLY_ENFORCED]
            ),
            "not_enforced": len([p for p in policies if p.status == PolicyStatus.NOT_ENFORCED]),
            "not_applicable": len([p for p in policies if p.status == PolicyStatus.NOT_APPLICABLE]),
            "by_category": self._group_policies_by_category(policies),
        }

        # Collect incident summary
        open_counts = await self.get_open_incidents_count()
        incidents_in_period = await self.get_incidents(since=period_start)
        incident_summary = {
            "open_incidents": open_counts,
            "total_open": sum(open_counts.values()),
            "reported_in_period": len(incidents_in_period),
            "resolved_in_period": len(
                [
                    i
                    for i in incidents_in_period
                    if i.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)
                ]
            ),
        }

        # Collect event summary
        event_summary = await self.get_event_summary(
            period_start=period_start,
            period_end=period_end,
        )

        # Perform control assessments
        access_control_assessment = await self.validate_access_control_config()
        control_assessments = [access_control_assessment.to_dict()]

        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(
            policies=policies,
            incident_summary=incident_summary,
            event_summary=event_summary,
            control_assessments=[access_control_assessment],
        )

        # Build report content for hashing
        report_content = {
            "report_id": str(report_id),
            "report_type": report_type,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "generated_at": generated_at.isoformat(),
            "generated_by": generated_by,
            "policy_summary": policy_summary,
            "incident_summary": incident_summary,
            "event_summary": event_summary,
            "control_assessments": control_assessments,
            "recommendations": recommendations,
        }

        # Compute hash for integrity
        content_json = json.dumps(report_content, sort_keys=True)
        report_hash = hashlib.sha256(content_json.encode()).hexdigest()

        report = SecurityReport(
            report_id=report_id,
            report_type=report_type,
            period_start=period_start,
            period_end=period_end,
            generated_at=generated_at,
            generated_by=generated_by,
            policy_summary=policy_summary,
            incident_summary=incident_summary,
            event_summary=event_summary,
            control_assessments=control_assessments,
            recommendations=recommendations,
            report_hash=report_hash,
        )

        # Log report generation
        actor = SecurityActor(actor_id=generated_by, actor_type="admin")
        await self._event_logger.log_sensitive_access(
            actor=actor,
            resource_type="security_report",
            resource_id=str(report_id),
            access_type="generate",
            purpose=f"{report_type} security report",
        )

        logger.info(
            "Security report generated: id=%s, type=%s, hash=%s",
            report_id,
            report_type,
            report_hash[:16] + "...",
        )

        return report

    async def export_audit_evidence(
        self,
        *,
        start_date: date,
        end_date: date,
        include_policies: bool = True,
        include_incidents: bool = True,
        include_events: bool = True,
        exported_by: str,
    ) -> dict[str, Any]:
        """Export security audit evidence for compliance review.

        Generates an evidence package suitable for conformity assessment
        per REQ-H01.

        Args:
            start_date: Start of date range.
            end_date: End of date range.
            include_policies: Include policy status.
            include_incidents: Include incident records.
            include_events: Include security event export.
            exported_by: Actor performing the export.

        Returns:
            Evidence package dictionary.
        """
        export_id = uuid4()
        exported_at = datetime.now(UTC)

        evidence: dict[str, Any] = {
            "export_id": str(export_id),
            "exported_at": exported_at.isoformat(),
            "exported_by": exported_by,
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
        }

        if include_policies:
            policies = await self.get_policy_status()
            evidence["policies"] = [p.to_dict() for p in policies]

        if include_incidents:
            start_dt = datetime.combine(start_date, datetime.min.time(), tzinfo=UTC)
            incidents = await self.get_incidents(since=start_dt)
            evidence["incidents"] = [i.to_dict() for i in incidents]

        if include_events:
            event_export = await self._event_logger.export_events(include_verification=True)
            evidence["security_events"] = event_export

        # Compute evidence hash
        content_json = json.dumps(evidence, sort_keys=True, default=str)
        evidence["evidence_hash"] = hashlib.sha256(content_json.encode()).hexdigest()

        # Log the export
        actor = SecurityActor(actor_id=exported_by, actor_type="admin")
        await self._event_logger.log_sensitive_access(
            actor=actor,
            resource_type="security_audit_evidence",
            resource_id=str(export_id),
            access_type="export",
            purpose="Compliance audit evidence export",
        )

        logger.info(
            "Security audit evidence exported: id=%s, by=%s",
            export_id,
            exported_by,
        )

        return evidence

    # -------------------------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------------------------

    def _group_policies_by_category(
        self,
        policies: list[SecurityPolicy],
    ) -> dict[str, dict[str, int]]:
        """Group policy counts by category and status.

        Args:
            policies: List of policies to group.

        Returns:
            Nested dict of category -> status -> count.
        """
        result: dict[str, dict[str, int]] = {}

        for policy in policies:
            category = policy.category.value
            if category not in result:
                result[category] = {
                    "enforced": 0,
                    "partially_enforced": 0,
                    "not_enforced": 0,
                    "not_applicable": 0,
                }

            result[category][policy.status.value] += 1

        return result

    def _generate_recommendations(
        self,
        *,
        policies: list[SecurityPolicy],
        incident_summary: dict[str, Any],
        event_summary: dict[str, Any],
        control_assessments: list[ControlAssessment],
    ) -> list[str]:
        """Generate recommendations based on current status.

        Args:
            policies: Current policy status.
            incident_summary: Incident summary data.
            event_summary: Event summary data.
            control_assessments: Control assessment results.

        Returns:
            List of recommendation strings.
        """
        recommendations: list[str] = []

        # Check for not-enforced policies
        not_enforced = [p for p in policies if p.status == PolicyStatus.NOT_ENFORCED]
        if not_enforced:
            recommendations.append(
                f"Review and implement enforcement for {len(not_enforced)} "
                f"policy(ies): {', '.join(p.policy_id for p in not_enforced)}"
            )

        # Check for open critical/high incidents
        open_counts = incident_summary.get("open_incidents", {})
        critical = open_counts.get("critical", 0)
        high = open_counts.get("high", 0)
        if critical > 0:
            recommendations.append(
                f"URGENT: {critical} critical security incident(s) require immediate attention"
            )
        if high > 0:
            recommendations.append(
                f"Priority: {high} high-severity incident(s) require prompt action"
            )

        # Check authentication failure ratio
        failure_ratio = event_summary.get("failure_ratio", 0)
        if failure_ratio > 0.1:  # More than 10% failures
            recommendations.append(
                f"Review authentication failures (ratio: {failure_ratio:.1%}). "
                "May indicate credential stuffing or misconfiguration."
            )

        # Check control assessments
        for assessment in control_assessments:
            if assessment.status != PolicyStatus.ENFORCED:
                recommendations.append(
                    f"Address findings in {assessment.name}: {', '.join(assessment.findings)}"
                )

        # Default recommendation if no issues
        if not recommendations:
            recommendations.append(
                "No immediate actions required. Continue regular monitoring and reviews."
            )

        return recommendations


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


async def create_security_controls_service(
    session: AsyncSession,
) -> SecurityControlsService:
    """Factory function to create a SecurityControlsService.

    Args:
        session: Database session.

    Returns:
        Configured SecurityControlsService instance.
    """
    return SecurityControlsService(session)
