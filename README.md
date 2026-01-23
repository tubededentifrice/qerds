# QERDS (eIDAS) / LRE (France) — high-level compliance tracker

This repository implements a **Qualified Electronic Registered Delivery Service (QERDS)** platform that can be operated by a provider seeking eIDAS qualification.

- Normative requirements live in `specs/requirements.md`.
- The table below is the project's living "compliance checklist": it MUST stay in sync with `specs/requirements.md`.

## Requirements status

Legend:
- ✅ Platform implements this requirement
- ❌ Not yet implemented
- 📋 **Operator obligation** — Platform provides tools/support, but the operator must execute the process. See the linked documentation.

### Service / platform requirements

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-A01 | Service operated by a qualified/supervised provider; no false "qualified" claims | 📋 | **Operator obligation**: Provider must obtain qualification. Platform enforces `QERDS_CLAIM_STATE` and non-qualified labeling. See `docs/compliance/qualification-guide.md` |
| REQ-A02 | Provider can pass required conformity assessments/audits | ✅ | Platform: `conformity_package.py`, APIs `POST /admin/conformity-packages`, `GET /admin/traceability-matrix`. See `docs/compliance/conformity-assessment.md` |
| REQ-A03 | Documented policies (security, incident, continuity, key/evidence mgmt) aligned with ETSI | 📋 | **Operator obligation**: Provider must maintain policy documents. Platform references them via policy versioning. See `docs/policies/` |
| REQ-A04 | Maintain traceability matrix (requirements → code/tests/audit artifacts) | ✅ | `REQUIREMENT_TRACEABILITY` in conformity_package.py, API `GET /admin/traceability-matrix` |
| REQ-B01 | Evidence supports proving sending/receiving + date/time | ✅ | `evidence.py` (EVT_DEPOSITED, EVT_RECEIVED), `lifecycle.py`. Tests in `tests/test_lifecycle.py`, `tests/test_evidence.py` |
| REQ-B02 | Protect against loss/theft/damage/unauthorised alteration; changes detectable | ✅ | `evidence_sealer.py` (SHA-256 content binding, CMS seal), `audit_log.py` (hash chain). Tests in `tests/test_evidence_sealer.py` |
| REQ-B03 | Identify sender and addressee as required | ✅ | `evidence.py:ActorIdentification`, party identity binding in evidence events. Tests in `tests/test_evidence.py` |
| REQ-B04 | Meet qualified conditions enabling eIDAS Article 44(2) presumption | ✅ | `qualified_mode.py`, `qualification.py` enforce HSM prerequisites. Operator must provision QSCD for production |
| REQ-B05 | Verify sender identity with very high confidence via permitted methods | ✅ | `oidc.py` (FranceConnect+ integration), IAL level enforcement. See `docs/identity/sender-proofing.md` |
| REQ-C01 | Evidence for all legally relevant lifecycle events | ✅ | `evidence.py` (EVT_* events for all states), `lifecycle.py`. Tests in `tests/test_lifecycle.py` |
| REQ-C02 | Evidence authenticity and attribution to provider (seal/signature as required) | ✅ | `evidence_sealer.py` (CMS seal), `trust.py` (key management). Tests in `tests/test_evidence_sealer.py` |
| REQ-C03 | Trustworthy time reference consistent with qualified requirements | ✅ | `trust.py` (RFC 3161 TSA stub). Operator must configure qualified TSA for production |
| REQ-C04 | ETSI EN 319 522 evidence/interop parts required by implementing rules | ✅ | `as4_sender.py`, `as4_receiver.py`, `smp_client.py` (Domibus gateway). See `docs/compliance/etsi-319-522-mapping.md` |
| REQ-C05 | Tamper-evident evidence/logs; protected from undetected deletion/modification | ✅ | `audit_log.py` SHA-256 hash chain, gap detection. Tests in `tests/test_audit_log.py` |
| REQ-D01 | Operate security management consistent with ETSI EN 319 401/319 521 | 📋 | **Operator obligation**: Provider must operate ISMS. Platform provides controls. See `specs/implementation/90-security-and-ops-controls.md`, `docs/operations/security-management.md` |
| REQ-D02 | Least privilege + strong auth + separation of duties | ✅ | `authz.py` (RBAC/ABAC), `session.py` (MFA, session mgmt). Operator must configure roles appropriately |
| REQ-D03 | Cryptographic mechanisms follow state-of-the-art per implementing rules | ✅ | AES-256-GCM, SHA-256, Ed25519. See `encryption.py`, `trust.py`, `docs/security/cryptographic-mechanisms.md` |
| REQ-D04 | Qualified-evidence keys in appropriately certified secure crypto device/module | ✅ | `qualified_mode.py` enforces HSM prerequisites in qualified mode. Operator must provision HSM/QSCD |
| REQ-D05 | Vulnerability scanning at least quarterly | 📋 | **Operator obligation**: Provider must perform quarterly scans. Platform tracks findings via `vulnerability_evidence.py`. See `docs/deployment/operator-checklist.md`, `docs/runbooks/vulnerability-scanning.md` |
| REQ-D06 | Penetration testing at least annually | 📋 | **Operator obligation**: Provider must arrange annual pentest. Platform tracks findings. See `docs/deployment/operator-checklist.md`, `docs/runbooks/penetration-testing.md` |
| REQ-D07 | Network filtering/firewalls default deny | ✅ | Docker compose binds to localhost; deployment docs specify default-deny. See `docs/deployment/network-security.md`, `docs/deployment/operator-checklist.md` |
| REQ-D08 | Security logging/monitoring protected and audit-ready | ✅ | `audit_log.py` (tamper-evident), `security_events.py`. Logs protected via hash chaining |
| REQ-D09 | Business continuity, backup, and disaster recovery controls | ✅ | `dr_evidence.py` for DR evidence. See `docs/runbooks/backup-dr.md` for procedures |
| REQ-E01 | Confidentiality against unauthorised access (including operators) | ✅ | `src/qerds/services/encryption.py`, `content_encryption.py` - AES-256-GCM envelope encryption, tests in `tests/test_encryption.py`, `test_content_encryption.py` |
| REQ-E02 | Recipient identification/authorisation gates content access | ✅ | `src/qerds/services/content_encryption.py:decrypt_for_user()` - authorization checks for sender/recipient, tests in `tests/test_content_encryption.py` |
| REQ-E03 | Notifications/endpoints minimise personal data exposure | ✅ | `email.py` omits sender identity and content preview from notifications (REQ-F03 compliance) |
| REQ-F01 | CPCE: recipient info + permanent access to proofs; third-party verification by ID | ✅ | `verify.py` (token-gated verification API), `pickup.py` (recipient portal). Tests in `tests/test_verify.py` |
| REQ-F02 | CPCE: notification includes required info and respects pre-acceptance constraints | ✅ | `email.py` (provider ID, delivery ref, legal nature, deadline). Tests in `tests/test_email.py` |
| REQ-F03 | CPCE: no sender identity disclosure before accept/refuse | ✅ | `pickup.py` (redaction until acceptance), `email.py` (no sender in notification). Tests in `tests/test_pickup.py` |
| REQ-F04 | CPCE: recipient has ≥ 15 days to accept/refuse | ✅ | `lifecycle.py:DEFAULT_ACCEPTANCE_WINDOW_DAYS=15`, enforced in state machine. Tests in `tests/test_lifecycle.py` |
| REQ-F05 | CPCE: proof of receipt retained/available ≥ 1 year | ✅ | `retention.py` (CPCE_MINIMUM_RETENTION_DAYS=365), `CPCEViolationError`. Tests in `tests/test_retention.py` |
| REQ-F06 | CPCE: consumer prior consent enforced and evidenced | ✅ | `consent.py` (consent state machine, audit trail). Tests in `tests/test_consent.py` |
| REQ-F07 | CPCE: human-readable evidence (PDF receipts) generated and sealed | ✅ | `pdf.py` (WeasyPrint), `evidence_sealer.py` (seal PDF artifacts). Tests in `tests/test_pdf.py` |
| REQ-G01 | No misleading claims in docs/UI about being qualified | ✅ | `qualification.py` (centralized labeling), template context injection. Operator must not claim qualification without certification |
| REQ-G02 | Non-qualified/dev modes clearly labeled; prevent "qualified" presentation | ✅ | `qualification.py:QualificationContext`, `trust.py:QualificationMode`. All outputs labeled per mode |

### Provider operational obligations (and technical enablers)

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-H01 | Audit pack export (evidence samples, config snapshots, crypto params, SBOM, etc.) | ✅ | `audit_pack.py`, API `POST /admin/audit-packs`. See `specs/implementation/80-audit-and-conformity.md` |
| REQ-H02 | Retention/retrieval controls for QERDS + CPCE LRE evidence/proofs | ✅ | `retention.py`, scheduled enforcement in worker. Operator configures retention policies |
| REQ-H03 | Tamper-evident operational/security logs with retention | ✅ | `audit_log.py` with SHA-256 hash chaining, `security_events.py`. See `specs/implementation/50-audit-logging-and-immutability.md` |
| REQ-H04 | Incident detection/triage and exportable timelines | ✅ | `security_events.py`, `alerting.py` (webhook alerts with HMAC), timeline export via `dispute.py`. Tests in `tests/test_alerting.py` |
| REQ-H05 | Change management artifacts (traceable deploys/config changes/rollback) | ✅ | `ops_events.py` (deployment markers, config snapshots), `admin.py` APIs. Tests in `tests/test_ops_events.py` |
| REQ-H06 | Admin access controls + access review reports | ✅ | `authz.py` (RBAC), `session.py`. Operator must perform periodic access reviews per `docs/deployment/operator-checklist.md` |
| REQ-H07 | Key lifecycle ceremony evidence support (generation/rotation/revocation) | ✅ | `trust.py`, APIs `GET /trust/keys`, `POST /trust/keys/{id}/rotate` |
| REQ-H08 | Backup/restore + DR exercise evidence suitable for audits | ✅ | `dr_evidence.py`, DR evidence APIs. See `docs/runbooks/backup-dr.md` for procedures |
| REQ-H09 | Vulnerability management evidence (scan/pentest/remediation tracking) | ✅ | `vulnerability_evidence.py`, `vulnerability.py` (finding model), admin APIs. See `docs/runbooks/vulnerability-scanning.md`, `docs/runbooks/penetration-testing.md` |
| REQ-H10 | Disputes/support evidence (timeline reconstruction, controlled exports) | ✅ | `dispute.py` for case export, timeline reconstruction, redaction profiles |

### System Architecture and Certification Maintenance

| Requirement ID | Requirement (high level) | Implemented | Comment |
|---|---|---|---|
| REQ-I01 | Clear backend/frontend separation; frontend updates don't invalidate backend cert | ✅ | API-first architecture (FastAPI backend), templates render HTML from API data. Frontend is untrusted |
| REQ-I02 | All possible requirements enforced on backend (frontend = untrusted) | ✅ | All authorization via `authz.py`, state machine in `lifecycle.py`, crypto in `trust.py`. Frontend cannot bypass |

### Project specifications (non-normative)

These are project-level decisions, not legal or certification requirements.

#### Internationalization (i18n)

| Spec ID | Specification | Implemented | Comment |
|---|---|---|---|
| SPEC-J01 | i18n from day 1; all user-facing text externalized for translation | ✅ | `api/i18n.py`, `locales/en.json`, `locales/fr.json`. Audit pending for completeness |
| SPEC-J02 | French and English supported for all user-facing content | ✅ | French (fr) and English (en) locales present. Audit pending for completeness |

---

## Operator Documentation

The following documentation supports providers in meeting their operational obligations for QERDS/LRE compliance.

### Existing Documentation

| Document | Purpose | Requirements Covered |
|---|---|---|
| `docs/deployment/operator-checklist.md` | Pre-deployment and periodic operational checklist | REQ-D05, REQ-D06, REQ-D07, REQ-H06, REQ-H08 |
| `docs/deployment/network-security.md` | Network security posture and default-deny configuration | REQ-D07 |
| `docs/runbooks/backup-dr.md` | Backup, restore, and disaster recovery procedures | REQ-D09, REQ-H08 |
| `docs/deployment/smp-setup.md` | SMP (Service Metadata Publishing) configuration | REQ-C04 |
| `docs/deployment/as4-gateway.md` | AS4 gateway (Domibus) setup for B2B interop | REQ-C04 |
| `specs/implementation/90-security-and-ops-controls.md` | Security and operational controls specification | REQ-D01, REQ-D02, REQ-D07, REQ-D08, REQ-D09, REQ-E01, REQ-H04, REQ-H05, REQ-H08 |
| `specs/implementation/80-audit-and-conformity.md` | Audit pack and conformity assessment support | REQ-A02, REQ-A03, REQ-A04, REQ-D05, REQ-D06, REQ-H01, REQ-H07, REQ-H08, REQ-H09, REQ-H10 |
| `docs/compliance/qualification-guide.md` | How to obtain QERDS qualification | REQ-A01, REQ-G01 |
| `docs/compliance/conformity-assessment.md` | Preparing for conformity assessments | REQ-A02, REQ-H01 |
| `docs/compliance/etsi-319-522-mapping.md` | ETSI EN 319 522 compliance mapping | REQ-C04 |
| `docs/policies/security-policy.md` | Information security policy template | REQ-A03, REQ-D01 |
| `docs/policies/incident-response.md` | Incident response policy template | REQ-A03, REQ-H04 |
| `docs/policies/business-continuity.md` | Business continuity policy template | REQ-A03, REQ-D09 |
| `docs/policies/key-management.md` | Key management policy template | REQ-A03, REQ-H07 |
| `docs/policies/evidence-management.md` | Evidence management policy template | REQ-A03, REQ-C01 |
| `docs/operations/security-management.md` | Operating an ISMS with the platform | REQ-D01, REQ-D02 |
| `docs/runbooks/vulnerability-scanning.md` | Quarterly vulnerability scanning procedures | REQ-D05, REQ-H09 |
| `docs/runbooks/penetration-testing.md` | Annual penetration testing procedures | REQ-D06, REQ-H09 |
| `docs/security/cryptographic-mechanisms.md` | Cryptographic algorithm choices and rationale | REQ-D03 |
| `docs/identity/sender-proofing.md` | Sender identity verification architecture | REQ-B05 |

### Operator Obligations Summary

Providers seeking QERDS/LRE qualification must:

1. **Obtain qualification** (REQ-A01): Complete conformity assessment and be listed in EU trusted lists
2. **Maintain policies** (REQ-A03): Document and maintain security, incident, continuity, and key management policies
3. **Operate ISMS** (REQ-D01): Run an information security management framework per ETSI EN 319 401
4. **Perform vulnerability scans** (REQ-D05): Quarterly scanning with remediation tracking
5. **Arrange penetration tests** (REQ-D06): Annual testing by qualified assessors
6. **Execute DR drills** (REQ-H08): Regular backup/restore testing and DR exercises
7. **Conduct access reviews** (REQ-H06): Periodic review of user access and permissions
8. **Manage changes** (REQ-H05): Track deployments, configuration changes, and maintain rollback capability

The platform provides technical support for these obligations through its APIs and services. See individual documentation for details.
