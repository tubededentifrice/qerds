# Claims, qualification modes, and guardrails

Covers: REQ-A01, REQ-B04, REQ-G01, REQ-G02, REQ-E03

## Objectives

This specification prevents:

1. Accidental or intentional presentation of the system as “qualified” when it is not (REQ-A01, REQ-G01).
2. Mixing qualified and non-qualified artifacts without explicit labeling and barriers (REQ-G02).

## Terminology

- **Operational qualification**: A property of the provider + operated service, not code. (REQ-A01)
- **Qualified-mode** (in platform configuration): A *restricted runtime mode* that enables qualified-only behaviors and disables dev/weak primitives. This mode MUST be possible only when the operator has provisioned compliant trust anchors and controls (e.g., qualified certificates, access controls). (REQ-B04, REQ-G02)
- **Non-qualified/dev mode**: Any mode that uses non-qualified keys, non-qualified timestamps, non-audited environments, or otherwise cannot satisfy qualified conditions. (REQ-G02)

## Requirements for claims and mode behavior

### 1) Global service claim state

The platform MUST have a single explicit, queryable **service claim state**:

- `claim_state = "non_qualified"` (default)
- `claim_state = "qualified"` (explicit, locked down)

This state MUST be:

- Configured by an operator-only workflow requiring explicit acknowledgment and artifacts attachment (e.g., “qualification dossier ID”, “trusted list listing reference”, assessment date). (REQ-A01, REQ-B04)
- Included in every UI surface where the service is named/marketed.
- Included in every evidence export and verification response as a non-normative informational field, so relying parties can detect non-qualified operation even if evidence is cryptographically valid. (REQ-G02, REQ-E03)

### 2) UI/UX wording guardrails

All user-facing surfaces (web UI, emails, PDFs, API docs, CLI output) MUST:

- Avoid the word “qualified” unless `claim_state="qualified"` and the operator has configured the required trust anchors. (REQ-G01)
- Use explicit labels such as “Non-qualified / dev mode” when not qualified. (REQ-G02)

### 3) Artifact labeling and anti-confusion

Every generated evidence object MUST include:

- `qualification_label`: one of `qualified` / `non_qualified`.
- `qualification_basis_ref` (optional): operator-provided reference for audits (e.g., trusted list entry id), only present when qualified.

Verification outputs MUST reject any attempt to present `non_qualified` artifacts as `qualified` (e.g., if a caller tries to override labels). (REQ-G02)

### 4) Public endpoints minimisation

Public verification endpoints MUST:

- Not reveal personal data by default; require an evidence identifier and a high-entropy verification token. (REQ-E03, REQ-F01)
- Return redacted views unless the caller proves authorization (see `specs/implementation/60-interop-and-verification.md`). (REQ-E03)

