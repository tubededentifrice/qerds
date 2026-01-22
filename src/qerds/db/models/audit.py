"""Audit-related models: log records, audit packs, and vulnerability evidence.

Covers: REQ-C05 (immutability), REQ-D08 (logging), REQ-H01 (exportability),
        REQ-H03 (audit review), REQ-D05 (vulnerability scanning),
        REQ-D06 (penetration testing), REQ-H09 (vulnerability management evidence)
"""

from __future__ import annotations

import enum
import uuid  # noqa: TC003 - required at runtime for SQLAlchemy type resolution

from sqlalchemy import BigInteger, Boolean, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from qerds.db.models.base import (
    AuditStream,
    Base,
    OptionalTimestampTZ,
    TimestampTZ,
    UUIDPrimaryKey,
)


class VulnArtifactType(enum.Enum):
    """Types of vulnerability management artifacts (REQ-D05, REQ-D06, REQ-H09).

    Values:
        VULN_SCAN: Vulnerability scan report (e.g., Trivy JSON/SARIF)
        SBOM: Software Bill of Materials (CycloneDX/SPDX)
        PENTEST_REPORT: Annual penetration test report
        PENTEST_SCOPE: Pentest scope and methodology documentation
        REMEDIATION_PLAN: Remediation plan for findings
        REMEDIATION_EVIDENCE: Evidence of remediation completion
        EXCEPTION: Risk acceptance/exception documentation
    """

    VULN_SCAN = "vuln_scan"
    SBOM = "sbom"
    PENTEST_REPORT = "pentest_report"
    PENTEST_SCOPE = "pentest_scope"
    REMEDIATION_PLAN = "remediation_plan"
    REMEDIATION_EVIDENCE = "remediation_evidence"
    EXCEPTION = "exception"


class SBOMFormat(enum.Enum):
    """SBOM format types.

    Values:
        CYCLONEDX_JSON: CycloneDX format in JSON
        CYCLONEDX_XML: CycloneDX format in XML
        SPDX_JSON: SPDX format in JSON
        SPDX_RDF: SPDX format in RDF
    """

    CYCLONEDX_JSON = "cyclonedx_json"
    CYCLONEDX_XML = "cyclonedx_xml"
    SPDX_JSON = "spdx_json"
    SPDX_RDF = "spdx_rdf"


class ScanOutputFormat(enum.Enum):
    """Vulnerability scan output formats.

    Values:
        TRIVY_JSON: Trivy native JSON format
        SARIF: Static Analysis Results Interchange Format
        CYCLONEDX: CycloneDX vulnerability format
    """

    TRIVY_JSON = "trivy_json"
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"


class AuditLogRecord(Base):
    """Tamper-evident audit log entry (REQ-C05, REQ-D08, REQ-H03).

    Each record is chained to the previous via prev_record_hash,
    creating an immutable, verifiable audit trail.
    """

    __tablename__ = "audit_log_records"

    record_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Stream categorization for efficient querying
    stream: Mapped[AuditStream] = mapped_column(
        Enum(AuditStream, name="audit_stream", create_constraint=True),
        nullable=False,
    )

    # Sequence number within the stream (monotonically increasing)
    # This enables detection of gaps/missing records
    seq_no: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Hash of this record's payload for integrity verification
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Hash of the previous record in this stream (chain link)
    # First record in a stream has NULL prev_record_hash
    prev_record_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Reference to full payload in object store
    # Payload is stored separately to keep the index table small
    payload_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Reference to sealed checkpoint that includes this record
    # Checkpoints are periodically created with timestamped signatures
    sealed_checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Event type for quick filtering without loading payload
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # Actor information for access review
    actor_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Resource reference (delivery_id, user_id, etc.)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Summary metadata for display without loading full payload
    summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_audit_log_records_stream", "stream"),
        # Unique sequence within each stream
        Index("ix_audit_log_records_stream_seq", "stream", "seq_no", unique=True),
        Index("ix_audit_log_records_created_at", "created_at"),
        Index("ix_audit_log_records_event_type", "event_type"),
        Index("ix_audit_log_records_actor", "actor_type", "actor_id"),
        Index("ix_audit_log_records_resource", "resource_type", "resource_id"),
        Index("ix_audit_log_records_checkpoint", "sealed_checkpoint_id"),
    )


class AuditPack(Base):
    """Exportable audit pack for external review (REQ-H01).

    Contains a range of audit records with sealed evidence,
    suitable for export to auditors or regulatory bodies.
    """

    __tablename__ = "audit_packs"

    audit_pack_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Time range covered by this pack
    range_start: Mapped[TimestampTZ]
    range_end: Mapped[TimestampTZ]

    # Stream(s) included in this pack
    streams: Mapped[list[str] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Who generated this pack
    generated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    generated_at: Mapped[TimestampTZ]

    # Reference to the pack archive in object store
    object_store_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Reference to sealed evidence object for the pack
    sealed_evidence_object_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_objects.evidence_object_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Pack metadata (record count, size, etc.)
    pack_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Human-readable description/notes
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Verification status
    verified_at: Mapped[OptionalTimestampTZ]
    verified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_audit_packs_range", "range_start", "range_end"),
        Index("ix_audit_packs_generated_at", "generated_at"),
    )


class VulnerabilityEvidence(Base):
    """Vulnerability management evidence artifact (REQ-D05, REQ-D06, REQ-H09).

    Stores metadata for vulnerability scan reports, SBOMs, penetration test
    reports, and remediation tracking artifacts. The actual artifact content
    is stored in object storage and referenced by storage_ref.

    Used to produce audit-ready evidence of vulnerability management activities
    for conformity assessments per Implementing Regulation 2025/1944.
    """

    __tablename__ = "vulnerability_evidence"

    vuln_evidence_id: Mapped[UUIDPrimaryKey]
    created_at: Mapped[TimestampTZ]

    # Artifact classification
    artifact_type: Mapped[VulnArtifactType] = mapped_column(
        Enum(VulnArtifactType, name="vuln_artifact_type", create_constraint=True),
        nullable=False,
    )

    # Human-readable title and description
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Reference to artifact in object storage
    storage_ref: Mapped[str] = mapped_column(String(500), nullable=False)

    # Content hash for integrity verification
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # File metadata
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Who uploaded this artifact
    uploaded_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # Scan-specific metadata (for vuln_scan type)
    scan_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    scan_tool_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    scan_output_format: Mapped[ScanOutputFormat | None] = mapped_column(
        Enum(ScanOutputFormat, name="scan_output_format", create_constraint=True),
        nullable=True,
    )

    # Trivy-specific metadata for air-gap compliance (REQ-H09)
    trivy_db_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trivy_db_tag: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # SBOM-specific metadata
    sbom_format: Mapped[SBOMFormat | None] = mapped_column(
        Enum(SBOMFormat, name="sbom_format", create_constraint=True),
        nullable=True,
    )

    # Scan scope and targets (images, containers, repos scanned)
    scan_scope: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # For quarterly scans, which quarter this covers (e.g., "2024-Q1")
    reporting_period: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Pentest-specific metadata
    pentest_firm: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pentest_start_date: Mapped[OptionalTimestampTZ]
    pentest_end_date: Mapped[OptionalTimestampTZ]
    pentest_methodology: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Findings summary (parsed from report)
    findings_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Remediation tracking
    remediation_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    remediation_due_date: Mapped[OptionalTimestampTZ]
    remediation_completed_at: Mapped[OptionalTimestampTZ]

    # Link to parent artifact (e.g., remediation plan links to pentest report)
    parent_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerability_evidence.vuln_evidence_id", ondelete="SET NULL"),
        nullable=True,
    )

    # Whether this artifact is included in audit pack exports by default
    include_in_audit_pack: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Additional artifact-specific metadata
    extra_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_vuln_evidence_artifact_type", "artifact_type"),
        Index("ix_vuln_evidence_created_at", "created_at"),
        Index("ix_vuln_evidence_reporting_period", "reporting_period"),
        Index("ix_vuln_evidence_parent", "parent_evidence_id"),
        Index("ix_vuln_evidence_audit_pack", "include_in_audit_pack"),
    )
