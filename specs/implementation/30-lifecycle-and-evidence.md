# Delivery lifecycle state machine and evidence events

Covers: REQ-B01, REQ-C01, REQ-E02, REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-F06, REQ-H10

## Core principle

Every legally relevant lifecycle event MUST emit evidence sufficient to reconstruct the timeline end-to-end. (REQ-C01)

## Domain objects (minimum)

- **Delivery**: one logical “registered delivery” item.
- **Submission / Deposit**: sender’s act of providing content and metadata.
- **Notification**: communication to recipient that something is available.
- **Decision**: recipient accept / refuse action.
- **Receipt**: recipient access and acknowledgement (where applicable).
- **Expiry / non-claim**: time window elapses without acceptance/receipt. (REQ-F04)

## Required state machine (minimum)

The delivery MUST have an explicit finite state machine with monotonic transitions:

- `draft` (created but not deposited)
- `deposited` (provider accepted submission; proof of deposit exists)
- `notified` (initial notification issued; evidence created)
- `notification_failed` (notification delivery failed, e.g., hard bounce; requires retry or manual handling)
- `available` (content available for retrieval under access gate)
- `accepted` or `refused` (recipient decision evidence)
- `received` (recipient actually obtained content; evidence includes date/time) (REQ-B01)
- `expired` (15-day minimum window passed without accept/refuse) (REQ-F04)

National profiles MAY add additional states but MUST not remove required evidence coverage. (REQ-C01)

## Evidence event catalog

For each delivery, the platform MUST produce evidence records for at least:

1. `EVT_DEPOSITED` — proof of deposit (REQ-B01, REQ-F01)
2. `EVT_NOTIFICATION_SENT` — notification issuance (REQ-C01, REQ-F02)
3. `EVT_NOTIFICATION_FAILED` — notification failure (e.g. bounce) (REQ-C01)
4. `EVT_AVAILABLE` — when content becomes available under access controls (REQ-C01, REQ-E02)
5. `EVT_ACCEPTED` — recipient acceptance (REQ-C01, REQ-F04)
6. `EVT_REFUSED` — recipient refusal (REQ-C01, REQ-F04)
7. `EVT_RECEIVED` — recipient receipt (REQ-B01, REQ-C01)
8. `EVT_EXPIRED` — non-claim/expiry (REQ-C01, REQ-F04)
9. `EVT_CONTENT_ACCESSED` — access audit event(s) linked to recipient identity session (REQ-E02, REQ-H10)

Each event MUST include:

- `event_id` (unique)
- `delivery_id`
- `event_type`
- `event_time` (see `specs/implementation/40-evidence-crypto-and-time.md`) (REQ-B01)
- `actor` (sender/recipient/provider system) with identification references (REQ-B03)
- `inputs_hashes` (hashes of relevant inputs/content pointers) (REQ-B02)
- `policy_snapshot_ref` (what policy/config applied at the time) (REQ-A03, REQ-H05)

## CPCE/LRE pre-acceptance constraints

Before recipient acceptance/refusal:

- The platform MUST NOT disclose sender identity to the recipient, and notification templates MUST comply with CPCE constraints. (REQ-F03, REQ-F02)
- The recipient MUST still be able to identify the provider and understand the legal nature of the delivery, consistent with CPCE notification rules. (REQ-F02)

This implies two separate metadata views:

- **Pre-acceptance view** (redacted)
- **Post-acceptance view** (full details)

## Notification evidence vs SMTP delivery

The platform MUST treat SMTP/email as a best-effort transport and MUST NOT rely on an external mail provider for compliance evidence retention. (REQ-C01, REQ-H02)

`EVT_NOTIFICATION_SENT` evidence SHOULD record:

- template/version identifier,
- recipient address reference (e.g., salted hash) and delivery channel,
- time attestation,
- and any outbound message identifiers in a privacy-preserving form (e.g., hashed), without storing message body content in logs. (REQ-E03, REQ-D08)

## Human-readable Evidence (PDFs)

In addition to structured evidence (XML/JSON), the platform MUST generate authoritative **PDF receipts** for download by the sender/recipient, as required by CPCE (REQ-F07).

Required artifacts:
- **Preuve de Dépôt (Proof of Deposit)**: Generated at `EVT_DEPOSITED`. Contains: sender/recipient ID, time of deposit.
- **Preuve d'Acceptation (Proof of Acceptance)**: Generated at `EVT_ACCEPTED`.
- **Preuve de Refus (Proof of Refusal)**: Generated at `EVT_REFUSED`.
- **Preuve de Négligence (Proof of Non-Claim)**: Generated at `EVT_EXPIRED`.
- **Preuve de Réception (Proof of Receipt)**: Generated at `EVT_RECEIVED` (content download).

These PDFs MUST:
- Be generated from the authoritative `evidence_events` data.
- Include a visible qualified electronic seal (or non-qualified in dev mode).
- Include the precise timestamps from the trust service.

## Disputes and reconstruction

The platform MUST support reconstructing a delivery timeline for disputes, by:

- enumerating all evidence events in order,
- providing verification outputs for each evidence object,
- producing a controlled disclosure export (see `specs/implementation/80-audit-and-conformity.md`). (REQ-H10)
