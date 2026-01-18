# Security and operational controls the platform must enable

Covers: REQ-D01, REQ-D02, REQ-D07, REQ-D08, REQ-D09, REQ-E01, REQ-H04, REQ-H05, REQ-H08

## Security management framework support

The platform MUST support an information security management framework (REQ-D01) by providing:

- a central configuration registry (versioned, attributable),
- security event telemetry and exportable audit logs (REQ-D08),
- incident workflow support: detection → triage → containment → evidence export (REQ-H04),
- secure defaults and hardening hooks for operator policy.

## Data Confidentiality Strategy (REQ-E01)

The platform implements **Operator-Managed Encryption** to balance security with operational requirements (virus scanning, format conversion).

- **Encryption at Rest**: All sensitive content (documents, metadata) MUST be encrypted in the storage layer (Postgres/MinIO) using strong symmetric encryption (e.g., AES-256-GCM).
- **Key Management**:
    - The Master Key (KEK) is managed by the `qerds-trust` service (ideally wrapping a key in an HSM/QSCD).
    - Data Encryption Keys (DEKs) are generated per object/delivery.
- **Access Control**:
    - The application (`qerds-api`) can only request decryption when processing an authenticated request from an authorized user (Sender/Recipient) or a necessary system process (e.g., virus scan job).
    - "Break-glass" access for operators is technically possible but MUST be strictly audited and trigger high-priority alerts.

## Network filtering / default deny (REQ-D07)

The deployed architecture MUST support default-deny network controls:

- minimal exposed ports,
- explicit service-to-service allowlists,
- auditable firewall / ingress configuration as part of change management artifacts (REQ-H05).

## Continuity, backup, and disaster recovery (REQ-D09, REQ-H08)

The platform MUST enable:

- automated backups for all durable state (DB, object store, config registry),
- restore testing with verifiable results and logs,
- DR exercises with exported evidence (timelines, RTO/RPO measurements). (REQ-H08)

## Administrative security controls

Administrative access MUST:

- require strong authentication,
- be least-privileged,
- have periodic access review exports. (REQ-D02, REQ-H06)
