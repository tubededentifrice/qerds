# Storage, retention, and retrieval

Covers: REQ-B02, REQ-C05, REQ-E01, REQ-F04, REQ-F05, REQ-H02

## Storage domains

The platform manages three primary storage domains:

1. **Content storage**: delivered payload (documents, attachments).
2. **Evidence storage**: evidence objects, verification bundles.
3. **Index/state storage**: delivery state machine, identities, access control, configuration snapshots.

Project constraints require production-ready storage (no SQLite); PostgreSQL is preferred for core state/evidence indexing. (project constraint)

## Confidentiality model for content

The platform MUST ensure confidentiality against unauthorized access (REQ-E01):

- Content MUST be encrypted at rest.
- Access to decryption keys MUST be restricted and audited.
- The platform MUST support a policy choice between:
  - provider-managed encryption (operator can decrypt under strict controls), or
  - end-to-end recipient encryption (operator cannot decrypt).

This is a non-obvious decision point because it affects operational support, disputes, and UX. (REQ-E01, REQ-H10)

## Retention schedules

The platform MUST enforce configurable retention schedules per artifact type (REQ-H02), including:

- proof of receipt retention for at least 1 year for CPCE LRE (REQ-F05),
- evidence retention for QERDS as required by applicable rules and provider policy.

Retention rules MUST be:

- versioned (so you can prove what policy applied historically),
- auditable,
- and enforceable (automated deletion/archival with logs).

## Deletion, archival, and immutability

For artifacts under retention:

- Deletion MUST be prohibited or made detectable via tamper-evident logs and sealed checkpoints. (REQ-C05)
- Archival MUST preserve future verifiability (store verification bundles and algorithm identifiers). (REQ-B02)

