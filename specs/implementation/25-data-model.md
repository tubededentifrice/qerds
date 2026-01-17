# Data model (PostgreSQL + object store)

Covers: REQ-B01, REQ-B02, REQ-B03, REQ-C01, REQ-C05, REQ-D02, REQ-D08, REQ-E02, REQ-F04, REQ-F05, REQ-F06, REQ-H02, REQ-H03, REQ-H05, REQ-H06, REQ-H10

## Principles

- PostgreSQL is the system of record for state, indexing, and auditability (no SQLite). (project constraint)
- Object store holds large immutable blobs (content, evidence bundles, audit packs), referenced by content-addressed hashes where possible. (REQ-B02, REQ-C05)

## Core tables (minimum viable)

### `deliveries`

- `delivery_id` (UUID, PK)
- `created_at`, `updated_at`
- `state` (enum: draft, deposited, notified, available, accepted, refused, received, expired)
- `sender_party_id`, `recipient_party_id` (FK)
- `jurisdiction_profile` (e.g., `eidass`, `fr_lre`) to enable CPCE-specific behavior
- `acceptance_deadline_at` (for 15-day window) (REQ-F04)
- `pre_acceptance_redaction_profile` (to enforce REQ-F03)

### `parties`

- `party_id` (UUID, PK)
- `party_type` (natural_person, legal_person)
- minimal identity fields with redaction support (REQ-E03)

### `sender_proofing`

- `party_id` (FK)
- `ial_level` (enum/int)
- `proofing_method` (enum)
- `proofing_evidence_object_ref` (object-store pointer)
- `proofed_at`

Supports “very high confidence” auditability. (REQ-B05)

### `recipient_consents`

- `recipient_party_id` (FK)
- `consent_type` (e.g., `fr_lre_electronic_delivery`)
- `consented_at`, `consented_by`
- `consent_evidence_object_ref`

Enforced for consumer recipients where applicable. (REQ-F06)

### `content_objects`

- `content_object_id` (UUID, PK)
- `delivery_id` (FK)
- `sha256` (or configured digest), `size_bytes`, `mime_type`
- `storage_key` (object-store key)
- `encryption_scheme` (enum)
- `encryption_metadata_ref` (e.g., recipient key id, wrapped DEK pointer)

Ensures integrity binding and confidentiality options. (REQ-B02, REQ-E01)

### `evidence_events`

- `event_id` (UUID, PK)
- `delivery_id` (FK)
- `event_type` (enum: EVT_DEPOSITED, EVT_NOTIFICATION_SENT, ...)
- `event_time` (timestamptz)
- `actor_type` (sender/recipient/system/admin)
- `actor_ref` (party_id or admin_user_id)
- `policy_snapshot_id` (FK)

### `evidence_objects`

- `evidence_object_id` (UUID, PK)
- `event_id` (FK)
- `canonical_payload_digest`
- `provider_attestation_blob_ref`
- `time_attestation_blob_ref`
- `verification_bundle_blob_ref`
- `qualification_label` (qualified/non_qualified) (REQ-G02)
- `created_at`

### `policy_snapshots`

- `policy_snapshot_id` (UUID, PK)
- `created_at`, `created_by`
- `doc_refs` (object-store refs to policy/CPS docs)
- `config_json` (minimal JSONB; keep stable schema)

Supports REQ-A03 and REQ-H05. (REQ-H05)

### `admin_users`, `api_clients`, `roles`, `role_bindings`

- RBAC/ABAC foundations and periodic access review export queries. (REQ-D02, REQ-H06)

### `audit_log_records` (tamper-evident stream index)

- `record_id` (UUID, PK)
- `stream` (evidence/security/ops)
- `seq_no` (bigint)
- `record_hash`, `prev_record_hash`
- `payload_ref` (object store)
- `sealed_checkpoint_id` (optional)

Supports immutability and audit review. (REQ-C05, REQ-H03, REQ-D08)

### `retention_policies` + `retention_actions`

- `artifact_type`, `minimum_retain_until`, `policy_version`
- `action_id`, `artifact_ref`, `action_type` (archive/delete), `executed_at`, `result`, `audit_log_record_id`

Supports CPCE one-year proof retention and auditability. (REQ-F05, REQ-H02)

### `audit_packs`

- `audit_pack_id` (UUID, PK)
- `range_start`, `range_end`
- `generated_by`, `generated_at`
- `object_store_ref`
- `sealed_evidence_object_id`

Supports exportability and immutability. (REQ-H01)

## Job queue tables (if Postgres-backed)

### `jobs`

- `job_id`, `job_type`, `run_at`, `locked_at`, `locked_by`, `attempts`, `payload_json`

Required for scheduled expiry, notifications retries, retention enforcement. (REQ-F04, REQ-H02)

