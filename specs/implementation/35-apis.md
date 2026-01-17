# HTTP APIs (FastAPI) and evidence surfaces

Covers: REQ-B01, REQ-B03, REQ-C01, REQ-C02, REQ-C03, REQ-C05, REQ-D02, REQ-D08, REQ-E02, REQ-E03, REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-H01, REQ-H03, REQ-H04, REQ-H05, REQ-H10

## API segmentation

Expose separate API namespaces (or separate services) with distinct auth:

- `/sender/*` — sender operations
- `/recipient/*` — recipient portal operations
- `/verify/*` — third-party verification (public but token-gated)
- `/admin/*` — operational/admin endpoints

This reduces accidental data exposure and simplifies policy enforcement. (REQ-E03, REQ-D02)

## Sender APIs (examples)

- `POST /sender/deliveries` → creates `draft` delivery (no evidence yet)
- `POST /sender/deliveries/{id}/deposit` → transitions to `deposited`, emits `EVT_DEPOSITED` with evidence (REQ-B01, REQ-C01)
- `POST /sender/deliveries/{id}/content` → upload content object, returns digest binding (REQ-B02)

Sender identity verification / onboarding surfaces MUST record proofing level and evidence references. (REQ-B05)

## Recipient APIs (examples)

- `GET /recipient/inbox` → list pending deliveries (redacted pre-acceptance) (REQ-F03)
- `POST /recipient/deliveries/{id}/accept` → emit `EVT_ACCEPTED`; unlock post-acceptance view (REQ-F04)
- `POST /recipient/deliveries/{id}/refuse` → emit `EVT_REFUSED` (REQ-F04)
- `GET /recipient/deliveries/{id}/content` → only allowed post-acceptance and after authZ checks (REQ-E02)

Acceptance window enforcement:

- APIs MUST reject accept/refuse after `acceptance_deadline_at` and instead emit/return `expired` state. (REQ-F04)

## Verification APIs (CPCE)

- `GET /verify/proofs/{proof_id}?token=...` → returns verification result with minimal PII (REQ-F01, REQ-E03)

Pre-acceptance rule:

- If the delivery is not accepted/refused yet, verification output MUST not reveal sender identity; return provider identity + delivery existence + timestamps + integrity status only. (REQ-F03)

## Admin / audit APIs

### Evidence and audit exports

- `POST /admin/audit-packs` → generate audit pack for a range; returns sealed pack reference (REQ-H01)
- `GET /admin/deliveries/{id}/timeline` → dispute reconstruction output with access control (REQ-H10)

### Security and change management

- `POST /admin/config/snapshots` → create versioned config snapshot; changes require attribution and are logged (REQ-H05, REQ-D08)
- `GET /admin/access-reviews/export` → export RBAC bindings and last-used timestamps for review (REQ-H06)

### Incident response support

- `POST /admin/incidents` / `GET /admin/incidents/{id}/export` → exportable incident timeline bundles (REQ-H04)

## Evidence object retrieval

- Evidence objects MUST be retrievable by stable identifier and verifiable offline using the verification bundle. (REQ-B01, REQ-C02, REQ-C03)
- Exports MUST include integrity proofs for audit log streams where required. (REQ-C05, REQ-H03)

