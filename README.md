# QERDS (eIDAS) / LRE (France) — high-level compliance tracker

This repository currently contains **high-level certification requirements** only (no implementation yet).

- Normative requirements live in `specs/requirements.md`.
- The table below is the project’s living “compliance checklist”: it MUST stay in sync with `specs/requirements.md`.

## Requirements status

Legend: ✅ implemented, ❌ not implemented.

### Service / platform requirements

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-A01 | Service operated by a qualified/supervised provider; no false “qualified” claims | ❌ |  |
| REQ-A02 | Provider can pass required conformity assessments/audits | ❌ |  |
| REQ-A03 | Documented policies (security, incident, continuity, key/evidence mgmt) aligned with ETSI | ❌ |  |
| REQ-A04 | Maintain traceability matrix (requirements → code/tests/audit artifacts) | ❌ |  |
| REQ-B01 | Evidence supports proving sending/receiving + date/time | ❌ |  |
| REQ-B02 | Protect against loss/theft/damage/unauthorised alteration; changes detectable | ❌ |  |
| REQ-B03 | Identify sender and addressee as required | ❌ |  |
| REQ-B04 | Meet qualified conditions enabling eIDAS Article 44(2) presumption | ❌ |  |
| REQ-B05 | Verify sender identity with very high confidence via permitted methods | ❌ |  |
| REQ-C01 | Evidence for all legally relevant lifecycle events | ❌ |  |
| REQ-C02 | Evidence authenticity and attribution to provider (seal/signature as required) | ❌ |  |
| REQ-C03 | Trustworthy time reference consistent with qualified requirements | ❌ |  |
| REQ-C04 | ETSI EN 319 522 evidence/interop parts required by implementing rules | ❌ |  |
| REQ-C05 | Tamper-evident evidence/logs; protected from undetected deletion/modification | ❌ |  |
| REQ-D01 | Operate security management consistent with ETSI EN 319 401/319 521 | ❌ |  |
| REQ-D02 | Least privilege + strong auth + separation of duties | ❌ |  |
| REQ-D03 | Cryptographic mechanisms follow state-of-the-art per implementing rules | ❌ |  |
| REQ-D04 | Qualified-evidence keys in appropriately certified secure crypto device/module | ❌ |  |
| REQ-D05 | Vulnerability scanning at least quarterly | ❌ |  |
| REQ-D06 | Penetration testing at least annually | ❌ |  |
| REQ-D07 | Network filtering/firewalls default deny | ❌ |  |
| REQ-D08 | Security logging/monitoring protected and audit-ready | ❌ |  |
| REQ-D09 | Business continuity, backup, and disaster recovery controls | ❌ |  |
| REQ-E01 | Confidentiality against unauthorised access (including operators) | ❌ |  |
| REQ-E02 | Recipient identification/authorisation gates content access | ❌ |  |
| REQ-E03 | Notifications/endpoints minimise personal data exposure | ❌ |  |
| REQ-F01 | CPCE: recipient info + permanent access to proofs; third-party verification by ID | ❌ |  |
| REQ-F02 | CPCE: notification includes required info and respects pre-acceptance constraints | ❌ |  |
| REQ-F03 | CPCE: no sender identity disclosure before accept/refuse | ❌ |  |
| REQ-F04 | CPCE: recipient has ≥ 15 days to accept/refuse | ❌ |  |
| REQ-F05 | CPCE: proof of receipt retained/available ≥ 1 year | ❌ |  |
| REQ-F06 | CPCE: consumer prior consent enforced and evidenced | ❌ |  |
| REQ-F07 | CPCE: human-readable evidence (PDF receipts) generated and sealed | ❌ |  |
| REQ-G01 | No misleading claims in docs/UI about being qualified | ❌ |  |
| REQ-G02 | Non-qualified/dev modes clearly labeled; prevent “qualified” presentation | ❌ |  |

### Provider operational obligations (and technical enablers)

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-H01 | Audit pack export (evidence samples, config snapshots, crypto params, SBOM, etc.) | ❌ |  |
| REQ-H02 | Retention/retrieval controls for QERDS + CPCE LRE evidence/proofs | ❌ |  |
| REQ-H03 | Tamper-evident operational/security logs with retention | ❌ |  |
| REQ-H04 | Incident detection/triage and exportable timelines | ❌ |  |
| REQ-H05 | Change management artifacts (traceable deploys/config changes/rollback) | ❌ |  |
| REQ-H06 | Admin access controls + access review reports | ❌ |  |
| REQ-H07 | Key lifecycle ceremony evidence support (generation/rotation/revocation) | ❌ |  |
| REQ-H08 | Backup/restore + DR exercise evidence suitable for audits | ❌ |  |
| REQ-H09 | Vulnerability management evidence (scan/pentest/remediation tracking) | ❌ |  |
| REQ-H10 | Disputes/support evidence (timeline reconstruction, controlled exports) | ❌ |  |

### System Architecture and Certification Maintenance

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-I01 | Clear backend/frontend separation; frontend updates don't invalidate backend cert | ❌ | Not applicable until certified |
| REQ-I02 | All possible requirements enforced on backend (frontend = untrusted) | ❌ |  |

### Project specifications (non-normative)

These are project-level decisions, not legal or certification requirements.

#### Internationalization (i18n)

| Spec ID | Specification | Implemented | Comment |
|---|---|---|---|
| SPEC-J01 | i18n from day 1; all user-facing text externalized for translation | ❌ |  |
| SPEC-J02 | French and English supported for all user-facing content | ❌ |  |
