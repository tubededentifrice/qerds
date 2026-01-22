"""Conformity assessment readiness package generation service.

Covers: REQ-A02 (conformity assessment readiness)

This module provides the conformity assessment package generation functionality
for auditors performing QERDS/LRE certification assessments. Per REQ-A02, the
provider must be able to pass required conformity assessments and audits.

A conformity assessment package contains:

- Requirement traceability matrix (REQ-A04): mapping from each requirement ID
  to implementation modules and verification artifacts
- Policy document references (REQ-A03): CPS, security policy, incident policy,
  continuity policy, key management policy, evidence management policy
- Evidence samples: representative sealed evidence from the audit pack
- System configuration snapshots: versioned configuration at assessment time
- Key inventory and ceremony evidence (REQ-H07): key lifecycle documentation
- Release/SBOM metadata: software bill of materials and version information

Conformity packages are:
- Designed for auditor consumption with human-readable documentation
- Sealed and timestamped for integrity
- Clearly labeled with qualification status (qualified/non-qualified)
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.services.storage import ObjectStoreClient
    from qerds.services.trust import TrustService

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Requirement Traceability Matrix (REQ-A04)
# -----------------------------------------------------------------------------

# Traceability matrix maps requirement IDs to implementation modules and tests.
# This is the source of truth for REQ-A04 compliance.
REQUIREMENT_TRACEABILITY: dict[str, dict[str, Any]] = {
    # Section A: Provider qualification, governance, auditability
    "REQ-A01": {
        "title": "Qualification status claims",
        "category": "governance",
        "modules": ["qerds.services.qualification", "qerds.services.trust"],
        "tests": ["tests/test_qualification.py", "tests/test_qualified_mode.py"],
        "evidence": ["qualification_label field on all evidence objects"],
    },
    "REQ-A02": {
        "title": "Conformity assessment readiness",
        "category": "governance",
        "modules": ["qerds.services.conformity_package", "qerds.services.audit_pack"],
        "tests": ["tests/test_conformity_package.py", "tests/test_audit_pack_service.py"],
        "evidence": ["conformity assessment packages", "audit packs"],
    },
    "REQ-A03": {
        "title": "Documented policies",
        "category": "governance",
        "modules": ["policies/"],
        "tests": [],
        "evidence": ["CPS", "security policy", "incident policy", "continuity policy"],
    },
    "REQ-A04": {
        "title": "Traceability matrix",
        "category": "governance",
        "modules": ["qerds.services.conformity_package.REQUIREMENT_TRACEABILITY"],
        "tests": ["tests/test_conformity_package.py::test_traceability_matrix"],
        "evidence": ["this matrix included in conformity packages"],
    },
    # Section B: Core eIDAS Article 44 guarantees
    "REQ-B01": {
        "title": "Sending/receiving proof with date/time",
        "category": "evidence",
        "modules": ["qerds.services.evidence", "qerds.services.lifecycle"],
        "tests": ["tests/test_evidence.py", "tests/test_lifecycle.py"],
        "evidence": ["evt_deposited", "evt_received", "evt_accepted events"],
    },
    "REQ-B02": {
        "title": "Integrity protection",
        "category": "security",
        "modules": ["qerds.services.evidence_sealer", "qerds.services.encryption"],
        "tests": ["tests/test_evidence_sealer.py", "tests/test_encryption.py"],
        "evidence": ["SHA-256 content hashes", "sealed evidence bundles"],
    },
    "REQ-B03": {
        "title": "Sender/addressee identification",
        "category": "identity",
        "modules": ["qerds.services.oidc", "qerds.db.models.parties"],
        "tests": ["tests/test_oidc.py"],
        "evidence": ["party identity verification records"],
    },
    "REQ-B04": {
        "title": "Qualified conditions for legal presumption",
        "category": "qualification",
        "modules": ["qerds.services.qualified_mode", "qerds.services.trust"],
        "tests": ["tests/test_qualified_mode.py"],
        "evidence": ["qualified seal/timestamp on evidence"],
    },
    "REQ-B05": {
        "title": "Sender identity verification methods",
        "category": "identity",
        "modules": ["qerds.services.oidc"],
        "tests": ["tests/test_oidc.py"],
        "evidence": ["identity verification method in evidence"],
    },
    # Section C: ERDS process and evidence lifecycle
    "REQ-C01": {
        "title": "Complete event coverage",
        "category": "evidence",
        "modules": ["qerds.services.lifecycle", "qerds.db.models.evidence"],
        "tests": ["tests/test_lifecycle.py", "tests/test_evidence.py"],
        "evidence": ["full event type coverage in delivery timeline"],
    },
    "REQ-C02": {
        "title": "Evidence authenticity (seal/signature)",
        "category": "crypto",
        "modules": ["qerds.services.trust", "qerds.services.evidence_sealer"],
        "tests": ["tests/test_trust.py", "tests/test_evidence_sealer.py"],
        "evidence": ["CMS signatures on evidence"],
    },
    "REQ-C03": {
        "title": "Trusted time reference",
        "category": "crypto",
        "modules": ["qerds.services.trust"],
        "tests": ["tests/test_trust.py"],
        "evidence": ["RFC 3161-style timestamp tokens"],
    },
    "REQ-C04": {
        "title": "ETSI EN 319 522 interoperability",
        "category": "interop",
        "modules": ["qerds.services.evidence"],
        "tests": ["tests/test_evidence.py"],
        "evidence": ["evidence format compliance"],
    },
    "REQ-C05": {
        "title": "Immutability of evidence/logs",
        "category": "audit",
        "modules": ["qerds.services.audit_log"],
        "tests": ["tests/test_audit_log.py"],
        "evidence": ["tamper-evident hash chains"],
    },
    # Section D: Security controls
    "REQ-D01": {
        "title": "Security management framework",
        "category": "security",
        "modules": ["policies/security-policy.md"],
        "tests": [],
        "evidence": ["security policy documentation"],
    },
    "REQ-D02": {
        "title": "Least privilege and strong auth",
        "category": "authz",
        "modules": ["qerds.services.authz", "qerds.api.middleware.auth"],
        "tests": ["tests/test_authz.py", "tests/test_rbac_authorization.py"],
        "evidence": ["RBAC enforcement, strong auth requirements"],
    },
    "REQ-D03": {
        "title": "State-of-the-art crypto mechanisms",
        "category": "crypto",
        "modules": ["qerds.services.trust"],
        "tests": ["tests/test_crypto.py", "tests/test_trust.py"],
        "evidence": ["algorithm suite version tracking"],
    },
    "REQ-D04": {
        "title": "Secure key storage (HSM for qualified)",
        "category": "crypto",
        "modules": ["qerds.services.trust"],
        "tests": ["tests/test_trust.py"],
        "evidence": ["key storage attestation in qualified mode"],
    },
    "REQ-D05": {
        "title": "Quarterly vulnerability scanning",
        "category": "security",
        "modules": ["policies/security-policy.md"],
        "tests": [],
        "evidence": ["vulnerability scan reports"],
    },
    "REQ-D06": {
        "title": "Annual penetration testing",
        "category": "security",
        "modules": ["policies/security-policy.md"],
        "tests": [],
        "evidence": ["penetration test reports"],
    },
    "REQ-D07": {
        "title": "Network filtering (default deny)",
        "category": "security",
        "modules": ["docker-compose.yml", "policies/security-policy.md"],
        "tests": [],
        "evidence": ["network policy documentation"],
    },
    "REQ-D08": {
        "title": "Security logging and monitoring",
        "category": "audit",
        "modules": ["qerds.services.security_events", "qerds.services.audit_log"],
        "tests": ["tests/test_security_events.py", "tests/test_audit_log.py"],
        "evidence": ["security audit log records"],
    },
    "REQ-D09": {
        "title": "Business continuity and DR",
        "category": "operations",
        "modules": ["policies/continuity-policy.md"],
        "tests": [],
        "evidence": ["DR test reports"],
    },
    # Section E: Confidentiality and access control
    "REQ-E01": {
        "title": "Content confidentiality",
        "category": "encryption",
        "modules": ["qerds.services.content_encryption", "qerds.services.encryption"],
        "tests": ["tests/test_encryption.py"],
        "evidence": ["encrypted content storage"],
    },
    "REQ-E02": {
        "title": "Access gating for recipients",
        "category": "authz",
        "modules": ["qerds.services.pickup", "qerds.api.routers.pickup"],
        "tests": ["tests/test_pickup_flow.py"],
        "evidence": ["auth wall before content access"],
    },
    "REQ-E03": {
        "title": "Data minimisation in notifications",
        "category": "privacy",
        "modules": ["qerds.services.email"],
        "tests": ["tests/test_email.py"],
        "evidence": ["notification content review"],
    },
    # Section F: France LRE (CPCE) requirements
    "REQ-F01": {
        "title": "Recipient info and permanent proof access",
        "category": "lre",
        "modules": ["qerds.api.routers.verify"],
        "tests": ["tests/test_verify_api.py"],
        "evidence": ["permanent verification URLs"],
    },
    "REQ-F02": {
        "title": "Notification content rules",
        "category": "lre",
        "modules": ["qerds.services.email", "qerds.templates/email"],
        "tests": ["tests/test_email.py"],
        "evidence": ["notification templates"],
    },
    "REQ-F03": {
        "title": "No sender identity pre-acceptance",
        "category": "lre",
        "modules": ["qerds.services.pickup"],
        "tests": ["tests/test_pickup_flow.py"],
        "evidence": ["sender identity gating in pickup flow"],
    },
    "REQ-F04": {
        "title": "15-day acceptance window",
        "category": "lre",
        "modules": ["qerds.services.lifecycle"],
        "tests": ["tests/test_lifecycle.py"],
        "evidence": ["expiry calculation in delivery"],
    },
    "REQ-F05": {
        "title": "1-year proof retention",
        "category": "retention",
        "modules": ["qerds.services.retention"],
        "tests": ["tests/test_retention.py"],
        "evidence": ["retention policy enforcement"],
    },
    "REQ-F06": {
        "title": "Consumer consent for LRE",
        "category": "lre",
        "modules": ["qerds.services.pickup"],
        "tests": ["tests/test_pickup_flow.py"],
        "evidence": ["consent records"],
    },
    "REQ-F07": {
        "title": "Human-readable PDF proofs",
        "category": "evidence",
        "modules": ["qerds.services.pdf"],
        "tests": [
            "tests/test_pdf.py",
            "tests/test_deposit_pdf.py",
            "tests/test_acceptance_pdf.py",
        ],
        "evidence": ["sealed PDF evidence artifacts"],
    },
    # Section G: Truth in claims
    "REQ-G01": {
        "title": "No misleading qualified claims",
        "category": "compliance",
        "modules": ["qerds.services.qualification"],
        "tests": ["tests/test_qualification.py"],
        "evidence": ["UI/docs review"],
    },
    "REQ-G02": {
        "title": "Non-qualified mode labeling",
        "category": "compliance",
        "modules": ["qerds.services.trust", "qerds.services.qualified_mode"],
        "tests": ["tests/test_qualified_mode.py"],
        "evidence": ["qualification_label on all outputs"],
    },
    # Section H: Provider operational obligations
    "REQ-H01": {
        "title": "Audit pack exportability",
        "category": "audit",
        "modules": ["qerds.services.audit_pack"],
        "tests": ["tests/test_audit_pack_service.py"],
        "evidence": ["audit pack generation"],
    },
    "REQ-H02": {
        "title": "Evidence retention controls",
        "category": "retention",
        "modules": ["qerds.services.retention"],
        "tests": ["tests/test_retention.py"],
        "evidence": ["retention policy configuration"],
    },
    "REQ-H03": {
        "title": "Tamper-evident operational logs",
        "category": "audit",
        "modules": ["qerds.services.audit_log"],
        "tests": ["tests/test_audit_log.py"],
        "evidence": ["hash chain verification"],
    },
    "REQ-H04": {
        "title": "Incident response support",
        "category": "operations",
        "modules": ["qerds.api.routers.admin"],
        "tests": ["tests/test_admin_api.py"],
        "evidence": ["incident records and exports"],
    },
    "REQ-H05": {
        "title": "Change management support",
        "category": "operations",
        "modules": ["qerds.db.models.evidence.PolicySnapshot"],
        "tests": ["tests/test_admin_api.py"],
        "evidence": ["config snapshots"],
    },
    "REQ-H06": {
        "title": "Access administration and reviews",
        "category": "authz",
        "modules": ["qerds.services.authz", "qerds.api.routers.admin"],
        "tests": ["tests/test_admin_api.py", "tests/test_authz.py"],
        "evidence": ["access review exports"],
    },
    "REQ-H07": {
        "title": "Key lifecycle ceremony evidence",
        "category": "crypto",
        "modules": ["qerds.services.trust"],
        "tests": ["tests/test_trust.py"],
        "evidence": ["key lifecycle event records"],
    },
    "REQ-H08": {
        "title": "Business continuity evidence",
        "category": "operations",
        "modules": ["policies/continuity-policy.md"],
        "tests": [],
        "evidence": ["DR exercise logs"],
    },
    "REQ-H09": {
        "title": "Vulnerability management evidence",
        "category": "security",
        "modules": ["policies/security-policy.md"],
        "tests": [],
        "evidence": ["scan/pentest reports"],
    },
    "REQ-H10": {
        "title": "Dispute/support evidence",
        "category": "operations",
        "modules": ["qerds.services.dispute", "qerds.api.routers.admin"],
        "tests": ["tests/test_dispute_service.py", "tests/test_admin_api.py"],
        "evidence": ["timeline reconstructions", "disclosure exports"],
    },
    # Section I: System architecture
    "REQ-I01": {
        "title": "Backend/frontend separation",
        "category": "architecture",
        "modules": ["src/qerds/api/", "src/qerds/templates/"],
        "tests": [],
        "evidence": ["architecture documentation"],
    },
    "REQ-I02": {
        "title": "Backend enforcement",
        "category": "architecture",
        "modules": ["qerds.api.middleware.auth", "qerds.services.authz"],
        "tests": ["tests/test_authz.py"],
        "evidence": ["backend validation for all operations"],
    },
}

# Policy documents that should be included in conformity packages
POLICY_DOCUMENTS: dict[str, dict[str, str]] = {
    "cps": {
        "title": "Certification Practice Statement",
        "path": "policies/cps/README.md",
        "publication_status": "published",
    },
    "security_policy": {
        "title": "Security Policy",
        "path": "policies/security-policy.md",
        "publication_status": "internal",
    },
    "incident_policy": {
        "title": "Incident Policy",
        "path": "policies/incident-policy.md",
        "publication_status": "internal",
    },
    "continuity_policy": {
        "title": "Business Continuity Policy",
        "path": "policies/continuity-policy.md",
        "publication_status": "internal",
    },
    "key_management_policy": {
        "title": "Key Management Policy",
        "path": "policies/key-management-policy.md",
        "publication_status": "internal",
    },
    "evidence_management_policy": {
        "title": "Evidence Management Policy",
        "path": "policies/evidence-management-policy.md",
        "publication_status": "internal",
    },
    "privacy_policy": {
        "title": "Privacy Policy",
        "path": "policies/privacy-policy.md",
        "publication_status": "published",
    },
}


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyDocumentInfo:
    """Information about a policy document included in the package.

    Attributes:
        doc_id: Unique identifier for the document type.
        title: Human-readable title.
        path: Path to the document in the repository.
        publication_status: Whether the document is published or internal.
        content_hash: SHA-256 hash of the document content.
        last_modified: When the document was last modified.
    """

    doc_id: str
    title: str
    path: str
    publication_status: str
    content_hash: str
    last_modified: datetime | None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "path": self.path,
            "publication_status": self.publication_status,
            "content_hash": self.content_hash,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
        }


@dataclass(frozen=True, slots=True)
class TraceabilityEntry:
    """Single entry in the requirement traceability matrix.

    Attributes:
        requirement_id: The requirement identifier (e.g., REQ-A01).
        title: Human-readable requirement title.
        category: Requirement category for grouping.
        modules: List of implementation module paths.
        tests: List of test file paths.
        evidence: List of evidence artifact descriptions.
        implementation_status: Current implementation status.
    """

    requirement_id: str
    title: str
    category: str
    modules: list[str]
    tests: list[str]
    evidence: list[str]
    implementation_status: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "requirement_id": self.requirement_id,
            "title": self.title,
            "category": self.category,
            "modules": self.modules,
            "tests": self.tests,
            "evidence": self.evidence,
            "implementation_status": self.implementation_status,
        }


@dataclass(frozen=True, slots=True)
class ConformityPackageContents:
    """Contents of a conformity assessment package.

    Attributes:
        traceability_matrix: Full requirement traceability matrix.
        policy_documents: Information about included policy documents.
        evidence_samples: Sample evidence from audit pack.
        config_snapshots: Configuration snapshots.
        key_inventory: Key inventory metadata.
        key_ceremony_events: Key lifecycle ceremony records.
        release_metadata: Release and SBOM information.
        system_info: System configuration and version information.
    """

    traceability_matrix: list[TraceabilityEntry]
    policy_documents: list[PolicyDocumentInfo]
    evidence_samples: list[dict[str, Any]]
    config_snapshots: list[dict[str, Any]]
    key_inventory: dict[str, Any]
    key_ceremony_events: list[dict[str, Any]]
    release_metadata: dict[str, Any]
    system_info: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SealedConformityPackage:
    """A sealed and timestamped conformity assessment package.

    Attributes:
        package_id: Unique identifier for this package.
        assessment_type: Type of assessment (e.g., initial, periodic, ad-hoc).
        created_at: When the package was generated.
        created_by: ID of the admin who generated the package.
        reason: Justification for generating the package.
        contents_summary: Summary counts and metadata.
        package_hash: SHA-256 hash of the package contents.
        seal_signature: Base64-encoded seal signature.
        timestamp_token: Timestamp attestation.
        storage_ref: Object storage reference for the package.
        qualification_label: Qualified or non-qualified status.
    """

    package_id: uuid.UUID
    assessment_type: str
    created_at: datetime
    created_by: str
    reason: str
    contents_summary: dict[str, Any]
    package_hash: str
    seal_signature: str
    timestamp_token: dict[str, Any]
    storage_ref: str
    qualification_label: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "package_id": str(self.package_id),
            "assessment_type": self.assessment_type,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "reason": self.reason,
            "contents_summary": self.contents_summary,
            "package_hash": self.package_hash,
            "seal_signature": self.seal_signature,
            "timestamp_token": self.timestamp_token,
            "storage_ref": self.storage_ref,
            "qualification_label": self.qualification_label,
        }


@dataclass
class ConformityPackageConfig:
    """Configuration for conformity package generation.

    Attributes:
        package_bucket: S3 bucket for storing packages.
        storage_prefix: Key prefix for package objects.
        max_evidence_samples: Maximum evidence events to include.
        max_ceremony_events: Maximum key ceremony events to include.
        app_version: Application version for release metadata.
        sbom_ref: Reference to SBOM location.
        policies_path: Path to the policies directory.
    """

    package_bucket: str = "qerds-conformity"
    storage_prefix: str = "conformity-packages/"
    max_evidence_samples: int = 100
    max_ceremony_events: int = 500
    app_version: str = "0.1.0"
    sbom_ref: str = "sbom/qerds-sbom.json"
    policies_path: str = "policies"


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class ConformityPackageError(Exception):
    """Base exception for conformity package operations."""

    pass


class ConformityPackageStorageError(ConformityPackageError):
    """Raised when package storage fails."""

    pass


# -----------------------------------------------------------------------------
# Service Implementation
# -----------------------------------------------------------------------------


class ConformityPackageService:
    """Service for generating conformity assessment readiness packages.

    Per REQ-A02, this service generates comprehensive packages for auditors
    performing QERDS/LRE conformity assessments. Packages include the
    traceability matrix (REQ-A04), policy documents, evidence samples,
    and key lifecycle documentation.

    Example:
        service = ConformityPackageService(db_session, trust_service, object_store)
        package = await service.generate_conformity_package(
            assessment_type="initial",
            created_by="admin-123",
            reason="Initial QERDS certification assessment",
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        trust_service: TrustService,
        object_store: ObjectStoreClient,
        config: ConformityPackageConfig | None = None,
        base_path: Path | None = None,
    ) -> None:
        """Initialize the conformity package service.

        Args:
            session: Database session for querying evidence and logs.
            trust_service: Trust service for sealing and timestamping.
            object_store: Object store client for package storage.
            config: Optional configuration (uses defaults if None).
            base_path: Base path for locating policy files. Defaults to cwd.
        """
        self._session = session
        self._trust_service = trust_service
        self._object_store = object_store
        self._config = config or ConformityPackageConfig()
        self._base_path = base_path or Path.cwd()

    async def generate_conformity_package(
        self,
        *,
        assessment_type: str,
        created_by: str,
        reason: str,
        include_evidence_samples: bool = True,
        include_key_ceremonies: bool = True,
    ) -> SealedConformityPackage:
        """Generate a sealed conformity assessment package.

        Collects all material needed for auditor review: traceability matrix,
        policy documents, evidence samples, configuration, and key lifecycle
        documentation.

        Args:
            assessment_type: Type of assessment (initial, periodic, ad-hoc).
            created_by: ID of the admin generating the package.
            reason: Justification for package generation (for audit trail).
            include_evidence_samples: Whether to include evidence samples.
            include_key_ceremonies: Whether to include key ceremony events.

        Returns:
            SealedConformityPackage with all contents and sealing attestations.

        Raises:
            ConformityPackageError: If package generation fails.
        """
        package_id = uuid.uuid4()
        created_at = datetime.now(UTC)

        logger.info(
            "Generating conformity package: package_id=%s, type=%s, by=%s",
            package_id,
            assessment_type,
            created_by,
        )

        # Build traceability matrix
        traceability_matrix = await self._build_traceability_matrix()

        # Collect policy documents
        policy_documents = await self._collect_policy_documents()

        # Collect evidence samples (if requested)
        evidence_samples = []
        if include_evidence_samples:
            evidence_samples = await self._collect_evidence_samples()

        # Collect config snapshots
        config_snapshots = await self._collect_config_snapshots()

        # Get key inventory
        key_inventory = await self._get_key_inventory()

        # Get key ceremony events (if requested)
        key_ceremony_events = []
        if include_key_ceremonies:
            key_ceremony_events = await self._collect_key_ceremony_events()

        # Get release metadata
        release_metadata = self._get_release_metadata()

        # Get system info
        system_info = await self._get_system_info()

        # Build package contents
        package_contents = ConformityPackageContents(
            traceability_matrix=traceability_matrix,
            policy_documents=policy_documents,
            evidence_samples=evidence_samples,
            config_snapshots=config_snapshots,
            key_inventory=key_inventory,
            key_ceremony_events=key_ceremony_events,
            release_metadata=release_metadata,
            system_info=system_info,
        )

        # Build manifest
        manifest = self._build_manifest(
            package_id=package_id,
            assessment_type=assessment_type,
            created_at=created_at,
            created_by=created_by,
            reason=reason,
            contents=package_contents,
        )

        # Compute package hash
        manifest_json = json.dumps(manifest, sort_keys=True, default=str)
        package_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

        # Seal the package
        seal_data = await self._trust_service.seal(manifest_json.encode())
        timestamp_token = await self._trust_service.timestamp(manifest_json.encode())

        # Create and store the package archive
        storage_ref = await self._store_package(
            package_id=package_id,
            manifest=manifest,
            package_contents=package_contents,
            seal_data=seal_data,
            timestamp_token=timestamp_token,
            assessment_type=assessment_type,
        )

        # Build contents summary
        contents_summary = {
            "requirement_count": len(traceability_matrix),
            "policy_document_count": len(policy_documents),
            "evidence_sample_count": len(evidence_samples),
            "config_snapshot_count": len(config_snapshots),
            "key_count": key_inventory.get("total_keys", 0),
            "ceremony_event_count": len(key_ceremony_events),
        }

        logger.info(
            "Conformity package generated: package_id=%s, hash=%s, storage_ref=%s",
            package_id,
            package_hash[:16] + "...",
            storage_ref,
        )

        return SealedConformityPackage(
            package_id=package_id,
            assessment_type=assessment_type,
            created_at=created_at,
            created_by=created_by,
            reason=reason,
            contents_summary=contents_summary,
            package_hash=package_hash,
            seal_signature=seal_data.signature,
            timestamp_token=timestamp_token.to_dict(),
            storage_ref=storage_ref,
            qualification_label=self._trust_service.mode.value,
        )

    async def _build_traceability_matrix(self) -> list[TraceabilityEntry]:
        """Build the requirement traceability matrix.

        Creates TraceabilityEntry objects from the REQUIREMENT_TRACEABILITY
        constant, determining implementation status for each requirement.

        Returns:
            List of TraceabilityEntry objects for all requirements.
        """
        entries = []
        for req_id, req_data in REQUIREMENT_TRACEABILITY.items():
            # Determine implementation status based on presence of modules/tests
            # This is a simplified heuristic; real status comes from README.md
            has_modules = bool(req_data.get("modules"))
            has_tests = bool(req_data.get("tests"))

            if has_modules and has_tests:
                status = "implemented"
            elif has_modules:
                status = "partial"
            else:
                status = "not_implemented"

            entries.append(
                TraceabilityEntry(
                    requirement_id=req_id,
                    title=req_data.get("title", ""),
                    category=req_data.get("category", ""),
                    modules=req_data.get("modules", []),
                    tests=req_data.get("tests", []),
                    evidence=req_data.get("evidence", []),
                    implementation_status=status,
                )
            )

        return entries

    async def _collect_policy_documents(self) -> list[PolicyDocumentInfo]:
        """Collect information about policy documents.

        Reads policy document metadata and computes content hashes.

        Returns:
            List of PolicyDocumentInfo for all policy documents.
        """
        documents = []

        for doc_id, doc_data in POLICY_DOCUMENTS.items():
            doc_path = self._base_path / doc_data["path"]

            # Compute content hash if file exists
            content_hash = ""
            last_modified = None

            if doc_path.exists():
                try:
                    content = doc_path.read_bytes()
                    content_hash = hashlib.sha256(content).hexdigest()
                    last_modified = datetime.fromtimestamp(doc_path.stat().st_mtime, tz=UTC)
                except OSError:
                    logger.warning("Could not read policy document: %s", doc_path)

            documents.append(
                PolicyDocumentInfo(
                    doc_id=doc_id,
                    title=doc_data["title"],
                    path=doc_data["path"],
                    publication_status=doc_data["publication_status"],
                    content_hash=content_hash,
                    last_modified=last_modified,
                )
            )

        return documents

    async def _collect_evidence_samples(self) -> list[dict[str, Any]]:
        """Collect sample evidence events for the package.

        Returns a representative sample of recent evidence events
        with their verification status.

        Returns:
            List of evidence sample summaries.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from qerds.db.models.evidence import EvidenceEvent

        query = (
            select(EvidenceEvent)
            .options(selectinload(EvidenceEvent.evidence_objects))
            .order_by(EvidenceEvent.event_time.desc())
            .limit(self._config.max_evidence_samples)
        )

        result = await self._session.execute(query)
        events = result.scalars().all()

        samples = []
        for event in events:
            sample = {
                "event_id": str(event.event_id),
                "event_type": event.event_type.value,
                "event_time": event.event_time.isoformat(),
                "delivery_id": str(event.delivery_id),
                "actor_type": event.actor_type.value,
                "evidence_object_count": len(event.evidence_objects),
                "qualification_labels": list(
                    {eo.qualification_label.value for eo in event.evidence_objects}
                ),
            }
            samples.append(sample)

        return samples

    async def _collect_config_snapshots(self) -> list[dict[str, Any]]:
        """Collect configuration snapshots.

        Returns:
            List of config snapshot summaries.
        """
        from sqlalchemy import select

        from qerds.db.models.evidence import PolicySnapshot

        query = select(PolicySnapshot).order_by(PolicySnapshot.created_at.desc()).limit(10)

        result = await self._session.execute(query)
        snapshots = result.scalars().all()

        return [
            {
                "snapshot_id": str(s.policy_snapshot_id),
                "version": s.version,
                "description": s.description,
                "created_at": s.created_at.isoformat(),
                "created_by": s.created_by,
                "snapshot_hash": s.snapshot_hash,
                "is_active": s.is_active,
            }
            for s in snapshots
        ]

    async def _get_key_inventory(self) -> dict[str, Any]:
        """Get key inventory metadata (no private material).

        Returns:
            Dictionary with key inventory summary.
        """
        inventory = await self._trust_service.get_key_inventory()
        return inventory.to_dict()

    async def _collect_key_ceremony_events(self) -> list[dict[str, Any]]:
        """Collect key lifecycle ceremony events.

        Returns key generation, activation, rotation, and revocation events
        with their attestation details.

        Returns:
            List of key ceremony event records.
        """
        # Get key lifecycle events from trust service
        try:
            events = await self._trust_service.get_key_lifecycle_events(
                limit=self._config.max_ceremony_events
            )
            return [e.to_dict() for e in events]
        except AttributeError:
            # Method might not exist on mock or older implementations
            logger.debug("get_key_lifecycle_events not available on trust service")
            return []

    def _get_release_metadata(self) -> dict[str, Any]:
        """Get release and SBOM metadata.

        Returns:
            Dictionary with release information.
        """
        return {
            "app_version": self._config.app_version,
            "sbom_ref": self._config.sbom_ref,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    async def _get_system_info(self) -> dict[str, Any]:
        """Get system configuration information.

        Returns:
            Dictionary with system configuration details.
        """
        # Get crypto params from trust service
        keys = await self._trust_service.get_keys()
        signing_keys = [k for k in keys if k.purpose.value == "signing"]

        crypto_info = {}
        if signing_keys:
            algo = signing_keys[0].algorithm
            crypto_info = {
                "suite_version": algo.version,
                "hash_algorithm": algo.hash_algorithm,
                "signature_algorithm": algo.signature_algorithm,
                "key_size": algo.key_size,
            }

        return {
            "qualification_mode": self._trust_service.mode.value,
            "crypto_suite": crypto_info,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def _build_manifest(
        self,
        *,
        package_id: uuid.UUID,
        assessment_type: str,
        created_at: datetime,
        created_by: str,
        reason: str,
        contents: ConformityPackageContents,
    ) -> dict[str, Any]:
        """Build the package manifest for sealing.

        Args:
            package_id: Package identifier.
            assessment_type: Type of assessment.
            created_at: Package creation time.
            created_by: Creator ID.
            reason: Generation reason.
            contents: Package contents.

        Returns:
            Manifest dictionary ready for JSON serialization.
        """
        return {
            "package_id": str(package_id),
            "version": "1.0",
            "type": "conformity_assessment_package",
            "assessment_type": assessment_type,
            "created_at": created_at.isoformat(),
            "created_by": created_by,
            "reason": reason,
            "contents": {
                "traceability_matrix": [e.to_dict() for e in contents.traceability_matrix],
                "policy_documents": [d.to_dict() for d in contents.policy_documents],
                "evidence_samples": contents.evidence_samples,
                "config_snapshots": contents.config_snapshots,
                "key_inventory": contents.key_inventory,
                "key_ceremony_events": contents.key_ceremony_events,
                "release_metadata": contents.release_metadata,
                "system_info": contents.system_info,
            },
            "statistics": {
                "requirement_count": len(contents.traceability_matrix),
                "policy_document_count": len(contents.policy_documents),
                "evidence_sample_count": len(contents.evidence_samples),
                "config_snapshot_count": len(contents.config_snapshots),
                "key_ceremony_event_count": len(contents.key_ceremony_events),
            },
        }

    async def _store_package(
        self,
        *,
        package_id: uuid.UUID,
        manifest: dict[str, Any],
        package_contents: ConformityPackageContents,
        seal_data: Any,
        timestamp_token: Any,
        assessment_type: str,
    ) -> str:
        """Store the conformity package to object storage as a ZIP archive.

        The archive contains:
        - manifest.json: Package manifest with all metadata
        - traceability_matrix.json: Full requirement traceability matrix
        - policy_documents/: Directory with policy document metadata
        - seal.json: Seal signature and verification bundle
        - timestamp.json: Timestamp token
        - auditor_guide.md: Instructions for auditors

        Args:
            package_id: Package identifier.
            manifest: Package manifest.
            package_contents: Full package contents.
            seal_data: Seal signature data.
            timestamp_token: Timestamp token.
            assessment_type: Type of assessment.

        Returns:
            Storage reference (S3 key) for the stored package.

        Raises:
            ConformityPackageStorageError: If storage fails.
        """
        # Build storage key
        date_str = datetime.now(UTC).strftime("%Y-%m-%d")
        storage_key = f"{self._config.storage_prefix}{package_id}/{assessment_type}_{date_str}.zip"

        # Create ZIP archive in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add manifest
            manifest_json = json.dumps(manifest, indent=2, sort_keys=True, default=str)
            zf.writestr("manifest.json", manifest_json)

            # Add traceability matrix as separate file for easy auditor access
            traceability_json = json.dumps(
                [e.to_dict() for e in package_contents.traceability_matrix],
                indent=2,
                sort_keys=True,
            )
            zf.writestr("traceability_matrix.json", traceability_json)

            # Add human-readable traceability matrix
            traceability_md = self._generate_traceability_markdown(
                package_contents.traceability_matrix
            )
            zf.writestr("traceability_matrix.md", traceability_md)

            # Add policy document index
            policy_index = json.dumps(
                [d.to_dict() for d in package_contents.policy_documents],
                indent=2,
                sort_keys=True,
            )
            zf.writestr("policy_documents/index.json", policy_index)

            # Add seal data
            seal_json = json.dumps(seal_data.to_dict(), indent=2, sort_keys=True)
            zf.writestr("seal.json", seal_json)

            # Add timestamp token
            timestamp_json = json.dumps(timestamp_token.to_dict(), indent=2, sort_keys=True)
            zf.writestr("timestamp.json", timestamp_json)

            # Add auditor guide
            auditor_guide = self._generate_auditor_guide(
                package_id=package_id,
                package_hash=manifest.get(
                    "package_hash", hashlib.sha256(manifest_json.encode()).hexdigest()
                ),
                assessment_type=assessment_type,
            )
            zf.writestr("auditor_guide.md", auditor_guide)

        # Upload to object storage
        zip_data = zip_buffer.getvalue()

        try:
            self._object_store.ensure_bucket(self._config.package_bucket)
            self._object_store.upload(
                bucket=self._config.package_bucket,
                key=storage_key,
                data=zip_data,
                content_type="application/zip",
                metadata={
                    "package-id": str(package_id),
                    "assessment-type": assessment_type,
                    "qualification-label": self._trust_service.mode.value,
                },
            )

            logger.info(
                "Stored conformity package: bucket=%s, key=%s, size=%d bytes",
                self._config.package_bucket,
                storage_key,
                len(zip_data),
            )

            return f"s3://{self._config.package_bucket}/{storage_key}"

        except Exception as e:
            msg = f"Failed to store conformity package {package_id}: {e}"
            raise ConformityPackageStorageError(msg) from e

    def _generate_traceability_markdown(self, matrix: list[TraceabilityEntry]) -> str:
        """Generate human-readable traceability matrix in Markdown format.

        Args:
            matrix: List of traceability entries.

        Returns:
            Markdown-formatted traceability matrix.
        """
        lines = [
            "# Requirement Traceability Matrix",
            "",
            "This document maps QERDS/LRE requirements to implementation artifacts.",
            "",
            "## Matrix Overview",
            "",
            "| Requirement | Title | Status | Modules | Tests |",
            "|-------------|-------|--------|---------|-------|",
        ]

        for entry in matrix:
            modules = ", ".join(entry.modules[:2])
            if len(entry.modules) > 2:
                modules += f" (+{len(entry.modules) - 2})"
            tests = ", ".join([t.split("/")[-1] for t in entry.tests[:2]])
            if len(entry.tests) > 2:
                tests += f" (+{len(entry.tests) - 2})"

            status_icon = {
                "implemented": "[x]",
                "partial": "[-]",
                "not_implemented": "[ ]",
            }.get(entry.implementation_status, "?")

            lines.append(
                f"| {entry.requirement_id} | {entry.title} | {status_icon} | {modules} | {tests} |"
            )

        lines.extend(
            [
                "",
                "## Detailed Entries",
                "",
            ]
        )

        # Group by category
        categories: dict[str, list[TraceabilityEntry]] = {}
        for entry in matrix:
            cat = entry.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(entry)

        for category, entries in sorted(categories.items()):
            lines.append(f"### {category.title()}")
            lines.append("")
            for entry in entries:
                lines.append(f"#### {entry.requirement_id}: {entry.title}")
                lines.append("")
                lines.append(f"**Status**: {entry.implementation_status}")
                lines.append("")
                lines.append("**Implementation Modules**:")
                for mod in entry.modules:
                    lines.append(f"- `{mod}`")
                lines.append("")
                lines.append("**Tests**:")
                for test in entry.tests:
                    lines.append(f"- `{test}`")
                if not entry.tests:
                    lines.append("- _No tests defined_")
                lines.append("")
                lines.append("**Evidence Artifacts**:")
                for ev in entry.evidence:
                    lines.append(f"- {ev}")
                if not entry.evidence:
                    lines.append("- _No evidence defined_")
                lines.append("")

        return "\n".join(lines)

    def _generate_auditor_guide(
        self,
        *,
        package_id: uuid.UUID,
        package_hash: str,
        assessment_type: str,
    ) -> str:
        """Generate instructions for auditors reviewing this package.

        Args:
            package_id: Package identifier.
            package_hash: SHA-256 hash of the manifest.
            assessment_type: Type of assessment.

        Returns:
            Markdown-formatted auditor guide.
        """
        qualification_note = self._get_qualification_note()

        return f"""# Conformity Assessment Package - Auditor Guide

## Package Information

- **Package ID**: {package_id}
- **Assessment Type**: {assessment_type}
- **Package Hash (SHA-256)**: {package_hash}
- **Qualification Status**: {self._trust_service.mode.value}

{qualification_note}

## Package Contents

This conformity assessment package contains all material needed to assess
QERDS/LRE compliance per REQ-A02:

1. **manifest.json**: Complete package manifest with metadata and contents
2. **traceability_matrix.json**: Machine-readable requirement traceability (REQ-A04)
3. **traceability_matrix.md**: Human-readable traceability matrix
4. **policy_documents/index.json**: Index of policy documents (REQ-A03)
5. **seal.json**: CMS signature over the manifest
6. **timestamp.json**: Timestamp token
7. **auditor_guide.md**: This guide

## Verification Steps

### 1. Verify Package Integrity

Compute the SHA-256 hash of `manifest.json` and compare:

```bash
sha256sum manifest.json
```

Expected: `{package_hash}`

### 2. Verify Seal Signature

The `seal.json` file contains the CMS signature. To verify:

1. Extract the certificate chain from `seal.json`
2. Verify the signature using the public key
3. Confirm the signing certificate is trusted

### 3. Verify Timestamp

The `timestamp.json` file contains the RFC 3161-style timestamp token.

### 4. Review Traceability Matrix

The `traceability_matrix.md` provides a human-readable mapping from each
requirement to implementation modules, tests, and evidence artifacts.

For each requirement under review:

1. Verify the listed modules exist in the codebase
2. Verify the listed tests exist and pass
3. Verify the evidence artifacts are generated and properly sealed

### 5. Review Policy Documents

Cross-reference `policy_documents/index.json` with the actual policy
documents in the repository to verify:

1. All required policies are present
2. Policies are appropriately versioned
3. Content hashes match

## Qualification Status

**This package was generated in {self._trust_service.mode.value} mode.**

{qualification_note}

## Contact

For questions about this conformity assessment package, contact the platform operator.
"""

    def _get_qualification_note(self) -> str:
        """Get qualification status note for documentation.

        Returns:
            Human-readable note about qualification status.
        """
        if self._trust_service.mode.value == "non_qualified":
            return (
                "**IMPORTANT**: This package was generated in non-qualified mode. "
                "All seals and timestamps are clearly labeled as non-qualified and "
                "are suitable for development/testing only. For actual QERDS/LRE "
                "qualification, the provider must operate in qualified mode with "
                "HSM-backed keys and qualified timestamp services."
            )
        return (
            "This package meets qualified electronic delivery service requirements. "
            "All seals and timestamps are backed by qualified trust services."
        )


# -----------------------------------------------------------------------------
# Factory Function
# -----------------------------------------------------------------------------


async def create_conformity_package_service(
    session: AsyncSession,
    trust_service: TrustService,
    object_store: ObjectStoreClient,
    *,
    package_bucket: str = "qerds-conformity",
    storage_prefix: str = "conformity-packages/",
    max_evidence_samples: int = 100,
    app_version: str = "0.1.0",
    base_path: Path | None = None,
) -> ConformityPackageService:
    """Factory function to create a ConformityPackageService.

    Args:
        session: Database session.
        trust_service: Trust service for sealing/timestamping.
        object_store: Object store client.
        package_bucket: S3 bucket for packages.
        storage_prefix: Key prefix for package objects.
        max_evidence_samples: Maximum evidence events per package.
        app_version: Application version for metadata.
        base_path: Base path for locating files.

    Returns:
        Configured ConformityPackageService instance.
    """
    config = ConformityPackageConfig(
        package_bucket=package_bucket,
        storage_prefix=storage_prefix,
        max_evidence_samples=max_evidence_samples,
        app_version=app_version,
    )
    return ConformityPackageService(session, trust_service, object_store, config, base_path)
