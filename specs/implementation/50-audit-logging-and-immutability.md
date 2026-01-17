# Audit logging, tamper evidence, and immutability

Covers: REQ-C05, REQ-D08, REQ-H03, REQ-H04, REQ-H05

## Goals

- Make evidence and operational/security logs tamper-evident for the full retention period. (REQ-C05, REQ-H03)
- Support audit and incident reconstruction (REQ-D08, REQ-H04).

## Audit log classes

The platform MUST maintain separate log streams at minimum:

- **Evidence log**: append-only log of evidence objects and evidence verification bundles.
- **Security log**: authentication/authorization events, admin actions, key operations. (REQ-D08)
- **Operations log**: deployments/config changes, backups, DR tests. (REQ-H05, REQ-H08)

## Tamper-evident construction

For each log stream, implement an append-only structure such as a hash chain or Merkle tree:

- Each record includes `prev_record_hash` (or inclusion proof) and the record hash.
- Periodic checkpoints are sealed/timestamped using the evidence crypto/time mechanisms. (REQ-C05, REQ-C03)
- Verification tooling MUST be able to prove log integrity over a range and detect deletion/reordering. (REQ-C05)

## Log access and disclosure

- Access to logs MUST be strictly controlled by RBAC/ABAC and purpose-of-access. (REQ-D02)
- Disclosure exports MUST support redaction and controlled release (for disputes or auditors). (REQ-H10, REQ-E03)

## Change management logging

Any change that can affect evidence generation/verification MUST produce:

- a versioned configuration snapshot reference,
- an attributable operator identity,
- a signed/timestamped change record,
- and a rollback record if rollback occurs. (REQ-H05)

