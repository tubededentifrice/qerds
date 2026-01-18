# System architecture (implementation-oriented)

Covers: REQ-A02, REQ-A03, REQ-B01, REQ-B02, REQ-C01, REQ-C05, REQ-D01, REQ-D02, REQ-D07, REQ-D08, REQ-D09, REQ-E01, REQ-E02, REQ-H01, REQ-H03, REQ-H04, REQ-H05, REQ-H08

## Goals

- Define service boundaries and trust boundaries so audits can reason about confidentiality, integrity, and traceability. (REQ-D01, REQ-E01, REQ-C05)
- Keep the stack lightweight and inspectable (audit-friendly), prioritizing Python standard library where practical.

## Proposed service decomposition (self-hostable)

### 1) `qerds-api` (FastAPI)

Primary responsibilities:

- Sender/recipient/admin/verifier HTTP API.
- Delivery lifecycle state machine enforcement. (REQ-C01)
- Evidence creation orchestration (calls trust services). (REQ-B01, REQ-C02, REQ-C03)
- Authorization, audit logging, and export endpoints. (REQ-D02, REQ-D08, REQ-H01)
- **Encryption Enforcement**: Handles decryption requests for authorized sessions only.

### 2) `qerds-worker` (Python, Postgres-backed job runner)

Primary responsibilities:

- Outbound notifications (email), retries, and scheduled transitions (e.g., expiry). (REQ-F04)
- Periodic sealing of tamper-evident log checkpoints. (REQ-C05)
- Retention enforcement jobs (archive/delete with audit trails). (REQ-H02)
- Backup/DR exercise helpers (generate evidence records for exercises). (REQ-H08)

Design constraint: prefer **no separate queue** (no Redis) by implementing a durable job table in PostgreSQL using `SKIP LOCKED` + advisory locks.

### 3) `qerds-trust` (signing/sealing + timestamping)

Primary responsibilities:

- Produce provider attestation (seal/signature) for evidence objects. (REQ-C02)
- Produce trustworthy time attestation (RFC3161 or other selected mechanism). (REQ-C03)
- Encapsulate key custody and HSM/QSCD integration. (REQ-D04, REQ-H07)
- **Key Encryption Key (KEK) Custody**: Manages the master keys used to protect data-at-rest keys.

This service MUST support:

- `non_qualified` mode: software keys for dev/test only, clearly labeled. (REQ-G02)
- `qualified` mode: keys only through certified crypto module/HSM via PKCS#11 and operator-provided qualified credentials; enforce “no software fallback”. (REQ-D04, REQ-G02)

### 4) Data stores

- `postgres` — authoritative state, evidence indexing, audit metadata. (project constraint)
- `object-store` — content blobs + evidence bundles (S3-compatible; MinIO allowed for dev). (project constraint)

### 5) Interop services (ETSI EN 319 522 profile dependent)

If QERDS interoperability with other providers is in scope, deploy:

- `as4-gateway` — an AS4 Message Service Handler (**selected: Domibus**). (REQ-C04)
- `smp` — an SMP/BDXR metadata publisher (**selected: phoss SMP**). (REQ-C04)

### 6) Email delivery (notifications & LRE)

Notifications are a transport mechanism; compliance-relevant evidence is generated and retained by the platform (e.g., `EVT_NOTIFICATION_SENT`), not by the SMTP provider. (REQ-C01, REQ-F02)

**Pickup Portal Strategy**:
- For LRE, email serves ONLY as a notification containing a "Claim Token" (Magic Link).
- The link directs the user to the `qerds-api` hosted **Pickup Portal**.
- **No Direct Access**: The link MUST NOT grant access to the content/sender-identity directly. The user MUST authenticate (FranceConnect+) to proceed.

Configuration requirement:

The platform MUST support configuring outbound SMTP so an operator can use:

- a self-hosted relay (e.g., Postal/Postfix), or
- a managed SMTP service (e.g., SES/Mailgun SMTP endpoints),

without changing application code. (REQ-D01)

Dev/test requirement:

- `mailpit` MUST be available for mail testing in `docker compose` environments. (project constraint)

Operational requirement:

- The SMTP component SHOULD be configured for minimal retention (no mailbox hosting; only transient queueing) and logs SHOULD be configured to avoid storing message bodies or unnecessary PII. (REQ-E03, REQ-D08)
- SMTP MUST be configured to require TLS for SMTP submission where supported by the provider/relay; credentials MUST be stored in the platform’s secret management mechanism (not in code). (REQ-D01, REQ-D02)

## Trust boundaries

- API boundary: untrusted internet → `qerds-api`.
- Private network boundary: `qerds-api` ↔ `postgres` / `object-store` / `qerds-trust`.
- Interop boundary: `qerds-api` ↔ `as4-gateway` and `smp` on a private network, with strict allowlists. (REQ-D07)
- Cryptographic boundary: only `qerds-trust` can access signing/timestamp keys in qualified mode. (REQ-D04)

## Network default deny (deployment goal)

The deployable topology MUST support:

- minimal exposed ports (API, optionally verifier endpoint),
- explicit allowlists for internal connectivity,
- auditable network policy changes as part of change management artifacts. (REQ-D07, REQ-H05)

## Auditability hooks

All components MUST emit:

- structured audit logs (append-only / tamper-evident stream references), (REQ-D08, REQ-H03)
- configuration snapshot references for any behavior-affecting change, (REQ-H05)
- export mechanisms for audit packs and incident timelines. (REQ-H01, REQ-H04)
