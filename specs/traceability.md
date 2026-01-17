# Traceability matrix (requirements → implementation specs)

This document maps each requirement ID from `specs/requirements.md` to the **implementation specification(s)** that define how the platform is intended to satisfy the requirement.

Notes:

- This repository currently contains **specifications only**. A requirement is not “implemented” until there is end-to-end code + tests + operational notes.
- Where a requirement depends on external normative documents (e.g., ETSI EN 319 521/522, Implementing Regulation (EU) 2025/1944), this matrix points to the spec section that describes *how* the project will integrate those requirements, but **does not reproduce** the normative text.

## Table

| Requirement ID | Covered by implementation specs |
|---|---|
| REQ-A01 | `specs/implementation/10-claims-and-modes.md` |
| REQ-A02 | `specs/implementation/80-audit-and-conformity.md` |
| REQ-A03 | `specs/implementation/80-audit-and-conformity.md`, `specs/implementation/05-architecture.md` |
| REQ-A04 | `specs/traceability.md`, `specs/implementation/00-index.md` |
| REQ-B01 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/25-data-model.md`, `specs/implementation/35-apis.md` |
| REQ-B02 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/70-storage-and-retention.md`, `specs/implementation/25-data-model.md` |
| REQ-B03 | `specs/implementation/20-identities-and-roles.md`, `specs/implementation/35-apis.md` |
| REQ-B04 | `specs/implementation/00-index.md`, `specs/implementation/80-audit-and-conformity.md` |
| REQ-B05 | `specs/implementation/20-identities-and-roles.md` |
| REQ-C01 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/35-apis.md`, `specs/implementation/25-data-model.md` |
| REQ-C02 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/45-trust-services.md`, `specs/implementation/35-apis.md` |
| REQ-C03 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/45-trust-services.md` |
| REQ-C04 | `specs/implementation/60-interop-and-verification.md`, `specs/implementation/65-etsi-interop-profile.md` |
| REQ-C05 | `specs/implementation/50-audit-logging-and-immutability.md`, `specs/implementation/70-storage-and-retention.md` |
| REQ-D01 | `specs/implementation/90-security-and-ops-controls.md` |
| REQ-D02 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/20-identities-and-roles.md` |
| REQ-D03 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/45-trust-services.md` |
| REQ-D04 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/45-trust-services.md`, `specs/implementation/05-architecture.md` |
| REQ-D05 | `specs/implementation/80-audit-and-conformity.md` |
| REQ-D06 | `specs/implementation/80-audit-and-conformity.md` |
| REQ-D07 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/05-architecture.md` |
| REQ-D08 | `specs/implementation/50-audit-logging-and-immutability.md`, `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/35-apis.md` |
| REQ-D09 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/80-audit-and-conformity.md` |
| REQ-E01 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/70-storage-and-retention.md`, `specs/implementation/05-architecture.md`, `specs/implementation/25-data-model.md` |
| REQ-E02 | `specs/implementation/20-identities-and-roles.md`, `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/35-apis.md` |
| REQ-E03 | `specs/implementation/10-claims-and-modes.md`, `specs/implementation/60-interop-and-verification.md`, `specs/implementation/35-apis.md`, `specs/implementation/65-etsi-interop-profile.md` |
| REQ-F01 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/60-interop-and-verification.md` |
| REQ-F02 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/35-apis.md` |
| REQ-F03 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/60-interop-and-verification.md`, `specs/implementation/35-apis.md` |
| REQ-F04 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/70-storage-and-retention.md`, `specs/implementation/35-apis.md`, `specs/implementation/25-data-model.md` |
| REQ-F05 | `specs/implementation/70-storage-and-retention.md`, `specs/implementation/25-data-model.md` |
| REQ-F06 | `specs/implementation/20-identities-and-roles.md`, `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/25-data-model.md` |
| REQ-G01 | `specs/implementation/10-claims-and-modes.md` |
| REQ-G02 | `specs/implementation/10-claims-and-modes.md`, `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/45-trust-services.md` |
| REQ-H01 | `specs/implementation/80-audit-and-conformity.md` |
| REQ-H02 | `specs/implementation/70-storage-and-retention.md`, `specs/implementation/25-data-model.md` |
| REQ-H03 | `specs/implementation/50-audit-logging-and-immutability.md`, `specs/implementation/25-data-model.md`, `specs/implementation/35-apis.md` |
| REQ-H04 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/80-audit-and-conformity.md` |
| REQ-H05 | `specs/implementation/90-security-and-ops-controls.md`, `specs/implementation/80-audit-and-conformity.md` |
| REQ-H06 | `specs/implementation/20-identities-and-roles.md`, `specs/implementation/80-audit-and-conformity.md`, `specs/implementation/25-data-model.md`, `specs/implementation/35-apis.md` |
| REQ-H07 | `specs/implementation/40-evidence-crypto-and-time.md`, `specs/implementation/80-audit-and-conformity.md`, `specs/implementation/45-trust-services.md` |
| REQ-H08 | `specs/implementation/80-audit-and-conformity.md`, `specs/implementation/90-security-and-ops-controls.md` |
| REQ-H09 | `specs/implementation/80-audit-and-conformity.md` |
| REQ-H10 | `specs/implementation/30-lifecycle-and-evidence.md`, `specs/implementation/80-audit-and-conformity.md`, `specs/implementation/35-apis.md`, `specs/implementation/25-data-model.md` |
