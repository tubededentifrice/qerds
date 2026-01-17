# Audit packs, conformity, and operational evidence

Covers: REQ-A02, REQ-A03, REQ-A04, REQ-D05, REQ-D06, REQ-D09, REQ-H01, REQ-H07, REQ-H08, REQ-H09, REQ-H10

## Audit pack export (REQ-H01)

The platform MUST provide an exportable “audit pack” that can be generated on demand for a defined time range.

Minimum audit pack contents:

- Evidence samples + verification bundles for a representative set of deliveries (REQ-H01)
- Evidence/log integrity proofs for the selected range (REQ-C05, REQ-H03)
- Versioned configuration snapshots that affect evidence generation and access control (REQ-H05)
- Cryptographic policy and algorithm suite configuration (REQ-D03)
- Key inventory metadata and key lifecycle ceremony logs (not private keys) (REQ-H07)
- Backup/restore/DR exercise reports and logs (REQ-H08, REQ-D09)
- Vulnerability scan reports, pentest reports, remediation tracker exports (REQ-D05, REQ-D06, REQ-H09)
- Incident timeline exports for incidents in-range (REQ-H04)
- Policy/CPS documents referenced by the platform at runtime (REQ-A03)
- SBOM and release build metadata for the audited version(s) (REQ-H01)

Audit packs MUST:

- be immutable once generated (sealed/timestamped),
- record who generated them, why, and under which authorization,
- support redaction profiles for different recipients (auditor vs support). (REQ-H10)

## Conformity assessment support (REQ-A02)

The platform MUST support producing the artifacts and evidence required for conformity assessments by:

- maintaining exportable controls evidence (logs, policies, configuration, test results),
- providing repeatable generation of audit packs and “controls snapshots”,
- enabling controlled demonstrations in a non-production assessment environment while preserving confidentiality. (REQ-A02, REQ-E01)

## Policies and CPS alignment (REQ-A03)

The platform MUST treat operator policies as first-class versioned artifacts:

- policy docs are stored and versioned,
- configuration snapshots reference a policy version,
- evidence objects reference which policy version applied at the time. (REQ-A03)

## Disputes/support exports (REQ-H10)

The platform MUST allow generating a case export that includes:

- the full event timeline,
- the set of evidence objects needed to prove the timeline,
- verification outputs and integrity proofs,
- with strict access control and redaction where required. (REQ-H10, REQ-E03)

