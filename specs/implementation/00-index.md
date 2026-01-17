# Implementation specifications (deep)

This directory converts the high-level requirements in `specs/requirements.md` into **implementation-oriented specifications**.

Guiding constraints (project-wide):

- The system MUST NOT be presented as “qualified” unless operated as a qualified, audited service. (REQ-A01, REQ-G01, REQ-G02)
- The specs assume a **self-hostable** platform: all runtime components are deployed by the operator. (project constraint)
- These documents specify *intended behaviors, data structures, and artifacts*; they do not claim compliance by themselves.

## Reading order

0. `specs/implementation/05-architecture.md` — service decomposition and trust boundaries. (REQ-D01, REQ-E01, REQ-C05)
0b. `specs/implementation/06-tech-stack.md` — dependency-minimal stack recommendations. (REQ-A02)
1. `specs/implementation/10-claims-and-modes.md` — how “qualified” vs “non-qualified/dev” modes are represented and prevented from being misused. (REQ-A01, REQ-G01, REQ-G02)
2. `specs/implementation/20-identities-and-roles.md` — parties, identities, verification levels, and authorization. (REQ-B03, REQ-B05, REQ-D02, REQ-E02, REQ-F06, REQ-H06)
3. `specs/implementation/30-lifecycle-and-evidence.md` — the delivery lifecycle state machine and required evidence events. (REQ-B01, REQ-C01, REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-F05, REQ-F06, REQ-H10)
4. `specs/implementation/40-evidence-crypto-and-time.md` — evidence cryptography and time sources. (REQ-B01/02, REQ-C02/03, REQ-D03/04)
5. `specs/implementation/50-audit-logging-and-immutability.md` — tamper-evident logging and immutability mechanisms. (REQ-C05, REQ-D08, REQ-H03)
6. `specs/implementation/60-interop-and-verification.md` — external verification and interoperability surfaces (incl. CPCE third-party verification). (REQ-C04, REQ-F01, REQ-E03)
7. `specs/implementation/65-etsi-interop-profile.md` — ETSI EN 319 522 profile selection and bindings. (REQ-C04)
8. `specs/implementation/70-storage-and-retention.md` — evidence/content storage, retention, and retrieval. (REQ-C05, REQ-H02, REQ-F05)
9. `specs/implementation/80-audit-and-conformity.md` — audit packs, conformity artifacts, and operational evidence. (REQ-A02/03/04, REQ-H01, REQ-H07-09)
10. `specs/implementation/90-security-and-ops-controls.md` — security controls and operational requirements the platform must enable. (REQ-D01-09, REQ-E01, REQ-H04-05-08)
11. `specs/implementation/25-data-model.md` — PostgreSQL + object store schema (audit-friendly). (REQ-B01, REQ-C05)
12. `specs/implementation/35-apis.md` — HTTP API surface definitions. (REQ-F01, REQ-E03)
13. `specs/implementation/45-trust-services.md` — self-hosted signing/sealing + timestamping services. (REQ-C02, REQ-C03, REQ-D04)
14. `specs/implementation/99-open-choices.md` — remaining decisions requiring confirmation.

## Traceability

- The single mapping source is `specs/traceability.md`. (REQ-A04)
