"""Audit pack generation service.

Covers: REQ-H01 (audit pack export for conformity assessment), REQ-D09, REQ-H08 (DR evidence)

This module provides the audit pack generation functionality for regulatory
review and conformity assessment. Per REQ-H01, audit packs must contain:

- Evidence samples + verification bundles for a representative set of deliveries
- Evidence/log integrity proofs for the selected range
- Versioned configuration snapshots
- Cryptographic policy and algorithm suite configuration
- Key inventory metadata and key lifecycle ceremony logs (not private keys)
- Policy/CPS documents referenced by the platform
- SBOM and release build metadata reference
- Backup/restore/DR exercise reports and logs (REQ-H08, REQ-D09)

Audit packs MUST be:
- Immutable once generated (sealed/timestamped)
- Record who generated them, why, and under which authorization
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import uuid
import zipfile
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.services.storage import ObjectStoreClient
    from qerds.services.trust import TrustService

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AuditPackContents:
    """Contents summary of a generated audit pack.

    Attributes:
        evidence_samples: List of evidence sample summaries.
        log_integrity_proofs: Verification results for audit log chains.
        config_snapshots: Configuration snapshots in the date range.
        crypto_params: Cryptographic algorithm suite configuration.
        key_inventory: Key metadata (no private material).
        policy_refs: References to policy documents.
        release_metadata: Release/SBOM information.
        dr_evidence: DR/backup exercise evidence (REQ-D09, REQ-H08).
    """

    evidence_samples: list[dict[str, Any]]
    log_integrity_proofs: dict[str, Any]
    config_snapshots: list[dict[str, Any]]
    crypto_params: dict[str, Any]
    key_inventory: dict[str, Any]
    policy_refs: dict[str, str]
    release_metadata: dict[str, Any]
    dr_evidence: list[dict[str, Any]] | None = None


@dataclass(frozen=True, slots=True)
class SealedAuditPack:
    """A sealed and timestamped audit pack.

    Attributes:
        pack_id: Unique identifier for this pack.
        start_date: Start of the date range (inclusive).
        end_date: End of the date range (inclusive).
        created_at: When the pack was generated.
        created_by: ID of the admin who generated the pack.
        reason: Justification for generating the pack.
        contents_summary: Summary counts and metadata.
        pack_hash: SHA-256 hash of the pack contents.
        seal_signature: Base64-encoded seal signature.
        timestamp_token: Timestamp attestation.
        storage_ref: Object storage reference for the pack.
        qualification_label: Qualified or non-qualified status.
        verification: Chain verification results.
    """

    pack_id: uuid.UUID
    start_date: date
    end_date: date
    created_at: datetime
    created_by: str
    reason: str
    contents_summary: dict[str, Any]
    pack_hash: str
    seal_signature: str
    timestamp_token: dict[str, Any]
    storage_ref: str
    qualification_label: str
    verification: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "pack_id": str(self.pack_id),
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "reason": self.reason,
            "contents_summary": self.contents_summary,
            "pack_hash": self.pack_hash,
            "seal_signature": self.seal_signature,
            "timestamp_token": self.timestamp_token,
            "storage_ref": self.storage_ref,
            "qualification_label": self.qualification_label,
            "verification": self.verification,
        }


@dataclass
class AuditPackConfig:
    """Configuration for audit pack generation.

    Attributes:
        audit_bucket: S3 bucket for storing audit packs.
        storage_prefix: Key prefix for audit pack objects.
        max_evidence_samples: Maximum evidence events to sample per pack.
        include_full_evidence: Whether to include full evidence payloads.
        app_version: Application version for release metadata.
        sbom_ref: Reference to SBOM location.
    """

    audit_bucket: str = "qerds-audit"
    storage_prefix: str = "audit-packs/"
    max_evidence_samples: int = 1000
    include_full_evidence: bool = True
    app_version: str = "0.1.0"
    sbom_ref: str = "sbom/qerds-sbom.json"


class AuditPackError(Exception):
    """Base exception for audit pack operations."""

    pass


class AuditPackStorageError(AuditPackError):
    """Raised when audit pack storage fails."""

    pass


class AuditPackService:
    """Service for generating and storing audit packs.

    Per REQ-H01, this service generates comprehensive audit packs containing
    all material needed for conformity assessment. Packs are sealed and
    timestamped to ensure immutability.

    Example:
        service = AuditPackService(db_session, trust_service, object_store)
        pack = await service.generate_audit_pack(
            start_date=date(2024, 1, 1),
            end_date=date(2024, 1, 31),
            created_by="admin-123",
            reason="Monthly compliance review",
        )
    """

    def __init__(
        self,
        session: AsyncSession,
        trust_service: TrustService,
        object_store: ObjectStoreClient,
        config: AuditPackConfig | None = None,
    ) -> None:
        """Initialize the audit pack service.

        Args:
            session: Database session for querying evidence and logs.
            trust_service: Trust service for sealing and timestamping.
            object_store: Object store client for pack storage.
            config: Optional configuration (uses defaults if None).
        """
        self._session = session
        self._trust_service = trust_service
        self._object_store = object_store
        self._config = config or AuditPackConfig()

    async def generate_audit_pack(
        self,
        *,
        start_date: date,
        end_date: date,
        created_by: str,
        reason: str,
        include_evidence: bool = True,
        include_security_logs: bool = True,
        include_ops_logs: bool = False,
        include_config_snapshots: bool = True,
        include_dr_evidence: bool = True,
    ) -> SealedAuditPack:
        """Generate a sealed audit pack for a date range.

        Collects evidence samples, audit logs, configuration snapshots,
        cryptographic parameters, and DR evidence, then seals and timestamps the pack.

        Args:
            start_date: Start of date range (inclusive).
            end_date: End of date range (inclusive).
            created_by: ID of the admin generating the pack.
            reason: Justification for pack generation (for audit trail).
            include_evidence: Whether to include evidence samples.
            include_security_logs: Whether to include security audit logs.
            include_ops_logs: Whether to include operational audit logs.
            include_config_snapshots: Whether to include config snapshots.
            include_dr_evidence: Whether to include DR/backup evidence (REQ-H08).

        Returns:
            SealedAuditPack with all contents and sealing attestations.

        Raises:
            AuditPackError: If pack generation fails.
        """
        pack_id = uuid.uuid4()
        created_at = datetime.now(UTC)

        # Convert dates to datetime range for queries
        start_dt = datetime.combine(start_date, datetime.min.time(), tzinfo=UTC)
        end_dt = datetime.combine(end_date, datetime.max.time(), tzinfo=UTC)

        logger.info(
            "Generating audit pack: pack_id=%s, range=%s to %s, by=%s",
            pack_id,
            start_date,
            end_date,
            created_by,
        )

        # Collect pack contents
        evidence_samples = []
        if include_evidence:
            evidence_samples = await self._collect_evidence_samples(start_dt, end_dt)

        # Verify and collect audit log integrity proofs
        log_proofs = await self._collect_log_integrity_proofs(
            include_security=include_security_logs,
            include_ops=include_ops_logs,
        )

        # Collect config snapshots
        config_snapshots = []
        if include_config_snapshots:
            config_snapshots = await self._collect_config_snapshots(start_dt, end_dt)

        # Get cryptographic parameters
        crypto_params = await self._get_crypto_params()

        # Get key inventory (metadata only, no private keys)
        key_inventory = await self._get_key_inventory()

        # Get policy document references
        policy_refs = self._get_policy_refs()

        # Get release/SBOM metadata
        release_metadata = self._get_release_metadata()

        # Collect DR evidence (REQ-D09, REQ-H08)
        dr_evidence = None
        if include_dr_evidence:
            dr_evidence = await self._collect_dr_evidence(start_dt, end_dt)

        # Build contents for sealing
        pack_contents = AuditPackContents(
            evidence_samples=evidence_samples,
            log_integrity_proofs=log_proofs,
            config_snapshots=config_snapshots,
            crypto_params=crypto_params,
            key_inventory=key_inventory,
            policy_refs=policy_refs,
            release_metadata=release_metadata,
            dr_evidence=dr_evidence,
        )

        # Build pack manifest
        manifest = self._build_manifest(
            pack_id=pack_id,
            start_date=start_date,
            end_date=end_date,
            created_at=created_at,
            created_by=created_by,
            reason=reason,
            contents=pack_contents,
        )

        # Compute pack hash
        manifest_json = json.dumps(manifest, sort_keys=True, default=str)
        pack_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

        # Seal the pack
        seal_data = await self._trust_service.seal(manifest_json.encode())
        timestamp_token = await self._trust_service.timestamp(manifest_json.encode())

        # Create ZIP archive and store to object storage
        storage_ref = await self._store_pack(
            pack_id=pack_id,
            manifest=manifest,
            pack_contents=pack_contents,
            seal_data=seal_data,
            timestamp_token=timestamp_token,
            start_date=start_date,
            end_date=end_date,
        )

        # Build verification summary
        verification = {
            "evidence_chain_valid": log_proofs.get("evidence", {}).get("valid", True),
            "security_chain_valid": log_proofs.get("security", {}).get("valid", True),
            "ops_chain_valid": log_proofs.get("ops", {}).get("valid", True),
            "errors": [],
        }
        for _stream_name, proof in log_proofs.items():
            if not proof.get("valid", True):
                verification["errors"].extend(proof.get("errors", []))

        # Build contents summary for response
        contents_summary = {
            "evidence_count": len(evidence_samples),
            "security_log_count": log_proofs.get("security", {}).get("record_count", 0),
            "ops_log_count": log_proofs.get("ops", {}).get("record_count", 0),
            "config_snapshot_count": len(config_snapshots),
            "key_count": key_inventory.get("total_keys", 0),
            "dr_evidence_count": len(dr_evidence) if dr_evidence else 0,
        }

        logger.info(
            "Audit pack generated: pack_id=%s, hash=%s, storage_ref=%s",
            pack_id,
            pack_hash[:16] + "...",
            storage_ref,
        )

        return SealedAuditPack(
            pack_id=pack_id,
            start_date=start_date,
            end_date=end_date,
            created_at=created_at,
            created_by=created_by,
            reason=reason,
            contents_summary=contents_summary,
            pack_hash=pack_hash,
            seal_signature=seal_data.signature,
            timestamp_token=timestamp_token.to_dict(),
            storage_ref=storage_ref,
            qualification_label=self._trust_service.mode.value,
            verification=verification,
        )

    async def _collect_evidence_samples(
        self,
        start_dt: datetime,
        end_dt: datetime,
    ) -> list[dict[str, Any]]:
        """Collect evidence event samples within the date range.

        Args:
            start_dt: Start datetime (inclusive).
            end_dt: End datetime (inclusive).

        Returns:
            List of evidence event summaries with verification bundles.
        """
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from qerds.db.models.evidence import EvidenceEvent

        query = (
            select(EvidenceEvent)
            .where(EvidenceEvent.event_time >= start_dt)
            .where(EvidenceEvent.event_time <= end_dt)
            .options(selectinload(EvidenceEvent.evidence_objects))
            .order_by(EvidenceEvent.event_time)
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
                "actor_ref": event.actor_ref,
                "evidence_objects": [
                    {
                        "object_id": str(eo.evidence_object_id),
                        "qualification_label": eo.qualification_label.value,
                        "storage_ref": eo.storage_ref,
                        "content_hash": eo.content_hash,
                    }
                    for eo in event.evidence_objects
                ],
            }
            if event.policy_snapshot_id:
                sample["policy_snapshot_id"] = str(event.policy_snapshot_id)
            samples.append(sample)

        return samples

    async def _collect_log_integrity_proofs(
        self,
        *,
        include_security: bool,
        include_ops: bool,
    ) -> dict[str, Any]:
        """Collect and verify audit log chain integrity.

        Args:
            include_security: Whether to include security log verification.
            include_ops: Whether to include ops log verification.

        Returns:
            Dictionary with verification results per stream.
        """
        from qerds.db.models.base import AuditStream
        from qerds.services.audit_log import AuditLogService

        audit_service = AuditLogService(self._session)
        proofs: dict[str, Any] = {}

        # Always verify evidence chain
        evidence_result = await audit_service.verify_chain(AuditStream.EVIDENCE)
        proofs["evidence"] = {
            "valid": evidence_result.valid,
            "record_count": evidence_result.checked_records,
            "first_seq": evidence_result.first_seq_no,
            "last_seq": evidence_result.last_seq_no,
            "errors": evidence_result.errors,
        }

        if include_security:
            security_result = await audit_service.verify_chain(AuditStream.SECURITY)
            proofs["security"] = {
                "valid": security_result.valid,
                "record_count": security_result.checked_records,
                "first_seq": security_result.first_seq_no,
                "last_seq": security_result.last_seq_no,
                "errors": security_result.errors,
            }

        if include_ops:
            ops_result = await audit_service.verify_chain(AuditStream.OPS)
            proofs["ops"] = {
                "valid": ops_result.valid,
                "record_count": ops_result.checked_records,
                "first_seq": ops_result.first_seq_no,
                "last_seq": ops_result.last_seq_no,
                "errors": ops_result.errors,
            }

        return proofs

    async def _collect_config_snapshots(
        self,
        start_dt: datetime,
        end_dt: datetime,
    ) -> list[dict[str, Any]]:
        """Collect configuration snapshots within the date range.

        Args:
            start_dt: Start datetime (inclusive).
            end_dt: End datetime (inclusive).

        Returns:
            List of config snapshot summaries.
        """
        from sqlalchemy import select

        from qerds.db.models.evidence import PolicySnapshot

        query = (
            select(PolicySnapshot)
            .where(PolicySnapshot.created_at >= start_dt)
            .where(PolicySnapshot.created_at <= end_dt)
            .order_by(PolicySnapshot.created_at)
        )

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
                "doc_refs": s.doc_refs,
            }
            for s in snapshots
        ]

    async def _get_crypto_params(self) -> dict[str, Any]:
        """Get current cryptographic algorithm suite configuration.

        Returns:
            Dictionary with algorithm suite details.
        """
        # Get key info to extract algorithm suite from active signing key
        keys = await self._trust_service.get_keys()
        signing_keys = [k for k in keys if k.purpose.value == "signing"]

        if signing_keys:
            algo = signing_keys[0].algorithm
            return {
                "suite_version": algo.version,
                "hash_algorithm": algo.hash_algorithm,
                "signature_algorithm": algo.signature_algorithm,
                "key_size": algo.key_size,
                "qualification_mode": self._trust_service.mode.value,
            }

        # Fallback to default
        from qerds.services.trust import AlgorithmSuite

        default_algo = AlgorithmSuite.default()
        return {
            "suite_version": default_algo.version,
            "hash_algorithm": default_algo.hash_algorithm,
            "signature_algorithm": default_algo.signature_algorithm,
            "key_size": default_algo.key_size,
            "qualification_mode": self._trust_service.mode.value,
        }

    async def _get_key_inventory(self) -> dict[str, Any]:
        """Get key inventory metadata (no private material).

        Returns:
            Dictionary with key inventory summary.
        """
        inventory = await self._trust_service.get_key_inventory()
        return inventory.to_dict()

    def _get_policy_refs(self) -> dict[str, str]:
        """Get references to policy documents.

        Returns:
            Dictionary mapping document type to storage reference.
        """
        # Policy document references would typically come from configuration
        # or a policy document registry. For now, return standard references.
        return {
            "cps": "policies/cps-v1.pdf",
            "terms_of_service": "policies/tos-v1.pdf",
            "privacy_policy": "policies/privacy-v1.pdf",
        }

    def _get_release_metadata(self) -> dict[str, Any]:
        """Get release and SBOM metadata.

        Returns:
            Dictionary with release information.
        """
        return {
            "app_version": self._config.app_version,
            "sbom_ref": self._config.sbom_ref,
            "build_timestamp": datetime.now(UTC).isoformat(),
        }

    async def _collect_dr_evidence(
        self,
        start_dt: datetime,
        end_dt: datetime,
    ) -> list[dict[str, Any]]:
        """Collect DR/backup evidence for the date range (REQ-D09, REQ-H08).

        Retrieves backup execution records, restore test results, and DR drill
        evidence within the specified date range for inclusion in the audit pack.

        Args:
            start_dt: Start datetime (inclusive).
            end_dt: End datetime (inclusive).

        Returns:
            List of DR evidence record dictionaries.
        """
        try:
            from qerds.services.dr_evidence import DREvidenceService

            # Create DR evidence service with the same session
            dr_service = DREvidenceService(self._session, self._object_store)

            # Get all DR evidence records for the date range
            records = await dr_service.get_records_for_audit_pack(start_dt, end_dt)

            logger.debug(
                "Collected %d DR evidence records for audit pack",
                len(records),
            )

            return records

        except ImportError:
            logger.warning("DR evidence service not available, skipping DR evidence collection")
            return []
        except Exception as e:
            logger.warning("Failed to collect DR evidence: %s", e)
            return []

    def _get_qualification_note(self) -> str:
        """Get qualification status note for verification instructions.

        Returns:
            Human-readable note about qualification status.
        """
        if self._trust_service.mode.value == "non_qualified":
            return "This is suitable for development/testing only."
        return "This pack meets qualified electronic delivery service requirements."

    def _build_manifest(
        self,
        *,
        pack_id: uuid.UUID,
        start_date: date,
        end_date: date,
        created_at: datetime,
        created_by: str,
        reason: str,
        contents: AuditPackContents,
    ) -> dict[str, Any]:
        """Build the pack manifest for sealing.

        Args:
            pack_id: Pack identifier.
            start_date: Range start date.
            end_date: Range end date.
            created_at: Pack creation time.
            created_by: Creator ID.
            reason: Generation reason.
            contents: Pack contents.

        Returns:
            Manifest dictionary ready for JSON serialization.
        """
        return {
            "pack_id": str(pack_id),
            "version": "1.0",
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "created_at": created_at.isoformat(),
            "created_by": created_by,
            "reason": reason,
            "contents": {
                "evidence_samples": contents.evidence_samples,
                "log_integrity_proofs": contents.log_integrity_proofs,
                "config_snapshots": contents.config_snapshots,
                "crypto_params": contents.crypto_params,
                "key_inventory": contents.key_inventory,
                "policy_refs": contents.policy_refs,
                "release_metadata": contents.release_metadata,
                "dr_evidence": contents.dr_evidence or [],
            },
            "statistics": {
                "evidence_sample_count": len(contents.evidence_samples),
                "config_snapshot_count": len(contents.config_snapshots),
                "dr_evidence_count": len(contents.dr_evidence) if contents.dr_evidence else 0,
            },
        }

    async def _store_pack(
        self,
        *,
        pack_id: uuid.UUID,
        manifest: dict[str, Any],
        pack_contents: AuditPackContents,  # noqa: ARG002 - reserved for future full evidence export
        seal_data: Any,
        timestamp_token: Any,
        start_date: date,
        end_date: date,
    ) -> str:
        """Store the audit pack to object storage as a ZIP archive.

        The archive contains:
        - manifest.json: Pack manifest with all metadata
        - seal.json: Seal signature and verification bundle
        - timestamp.json: Timestamp token
        - verification_instructions.md: How to verify the pack

        Args:
            pack_id: Pack identifier.
            manifest: Pack manifest.
            pack_contents: Full pack contents.
            seal_data: Seal signature data.
            timestamp_token: Timestamp token.
            start_date: Range start date.
            end_date: Range end date.

        Returns:
            Storage reference (S3 key) for the stored pack.

        Raises:
            AuditPackStorageError: If storage fails.
        """
        # Build storage key
        date_range = f"{start_date.isoformat()}_{end_date.isoformat()}"
        storage_key = f"{self._config.storage_prefix}{pack_id}/{date_range}.zip"

        # Create ZIP archive in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add manifest
            manifest_json = json.dumps(manifest, indent=2, sort_keys=True, default=str)
            zf.writestr("manifest.json", manifest_json)

            # Add seal data
            seal_json = json.dumps(seal_data.to_dict(), indent=2, sort_keys=True)
            zf.writestr("seal.json", seal_json)

            # Add timestamp token
            timestamp_json = json.dumps(timestamp_token.to_dict(), indent=2, sort_keys=True)
            zf.writestr("timestamp.json", timestamp_json)

            # Add verification instructions
            instructions = self._generate_verification_instructions(
                pack_id=pack_id,
                pack_hash=manifest.get(
                    "pack_hash", hashlib.sha256(manifest_json.encode()).hexdigest()
                ),
            )
            zf.writestr("verification_instructions.md", instructions)

        # Upload to object storage
        zip_data = zip_buffer.getvalue()

        try:
            self._object_store.ensure_bucket(self._config.audit_bucket)
            self._object_store.upload(
                bucket=self._config.audit_bucket,
                key=storage_key,
                data=zip_data,
                content_type="application/zip",
                metadata={
                    "pack-id": str(pack_id),
                    "start-date": start_date.isoformat(),
                    "end-date": end_date.isoformat(),
                    "qualification-label": self._trust_service.mode.value,
                },
            )

            logger.info(
                "Stored audit pack: bucket=%s, key=%s, size=%d bytes",
                self._config.audit_bucket,
                storage_key,
                len(zip_data),
            )

            return f"s3://{self._config.audit_bucket}/{storage_key}"

        except Exception as e:
            msg = f"Failed to store audit pack {pack_id}: {e}"
            raise AuditPackStorageError(msg) from e

    def _generate_verification_instructions(
        self,
        *,
        pack_id: uuid.UUID,
        pack_hash: str,
    ) -> str:
        """Generate verification instructions for auditors.

        Args:
            pack_id: Pack identifier.
            pack_hash: SHA-256 hash of the manifest.

        Returns:
            Markdown-formatted verification instructions.
        """
        return f"""# Audit Pack Verification Instructions

## Pack Information
- **Pack ID**: {pack_id}
- **Pack Hash (SHA-256)**: {pack_hash}
- **Qualification Status**: {self._trust_service.mode.value}

## Verification Steps

### 1. Verify Pack Integrity
Compute the SHA-256 hash of `manifest.json` and compare with the pack hash above:

```bash
sha256sum manifest.json
```

The output should match: `{pack_hash}`

### 2. Verify Seal Signature
The `seal.json` file contains the CMS signature over the manifest.
To verify:

1. Extract the certificate chain from `seal.json`
2. Verify the signature using the public key from the certificate
3. Confirm the signing certificate is trusted

### 3. Verify Timestamp
The `timestamp.json` file contains the RFC 3161-style timestamp token.
This attests to the time the pack was generated.

### 4. Verify Audit Log Chains
The manifest contains log integrity proofs in `contents.log_integrity_proofs`.
Check that:
- All chains show `valid: true`
- No gaps or errors are reported

## Important Notes

- **Qualification Status**: This pack was generated in **{self._trust_service.mode.value}** mode.
  {self._get_qualification_note()}

- **Evidence Samples**: Not all evidence is included; this pack contains a sample
  of evidence events within the specified date range.

- **Key Inventory**: Contains metadata only. No private key material is included.

## Contact
For questions about this audit pack, contact the platform operator.
"""


async def create_audit_pack_service(
    session: AsyncSession,
    trust_service: TrustService,
    object_store: ObjectStoreClient,
    *,
    audit_bucket: str = "qerds-audit",
    storage_prefix: str = "audit-packs/",
    max_evidence_samples: int = 1000,
    app_version: str = "0.1.0",
) -> AuditPackService:
    """Factory function to create an AuditPackService.

    Args:
        session: Database session.
        trust_service: Trust service for sealing/timestamping.
        object_store: Object store client.
        audit_bucket: S3 bucket for audit packs.
        storage_prefix: Key prefix for pack objects.
        max_evidence_samples: Maximum evidence events per pack.
        app_version: Application version for metadata.

    Returns:
        Configured AuditPackService instance.
    """
    config = AuditPackConfig(
        audit_bucket=audit_bucket,
        storage_prefix=storage_prefix,
        max_evidence_samples=max_evidence_samples,
        app_version=app_version,
    )
    return AuditPackService(session, trust_service, object_store, config)
