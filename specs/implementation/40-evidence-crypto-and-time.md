# Evidence cryptography, sealing/signing, and trusted time

Covers: REQ-B01, REQ-B02, REQ-C02, REQ-C03, REQ-D03, REQ-D04, REQ-G02, REQ-H07

## Scope

This specification defines:

- how evidence objects are hashed, sealed/signed, and timestamped,
- how cryptographic agility and “state of the art” are handled,
- how key lifecycle and key custody evidence is produced.

It does not embed ETSI standard text; it defines implementation hooks that must be aligned with the applicable documents. (REQ-D03)

## Evidence object structure (logical)

Each evidence object MUST be represented as:

- **payload**: structured fields describing the event (see `specs/implementation/30-lifecycle-and-evidence.md`)
- **canonicalization**: a deterministic method to produce bytes for hashing/signing (MUST be specified and versioned)
- **content binding**: cryptographic binding to content (hashes + storage pointers) (REQ-B02)
- **provider attestation**: provider seal/signature (REQ-C02)
- **time attestation**: timestamp or equivalent trustworthy time reference (REQ-C03)
- **verification bundle**: chain material required to verify later (certs, policies, algorithm identifiers)
- **qualification label**: `qualified` / `non_qualified` (REQ-G02)

## Hashing and content integrity

The platform MUST:

- compute and store a cryptographic digest of all delivered content and legally relevant metadata (REQ-B02),
- bind that digest into evidence objects for every lifecycle event where content/metadata is relevant (REQ-B01, REQ-C01).

Algorithm selection MUST be centrally configured and versioned; changing algorithms MUST not break later verification of historical evidence. (REQ-D03)

## Seals/signatures (provider authenticity)

Evidence MUST be attributable to the provider through a cryptographic mechanism suitable for the applicable profile (REQ-C02):

- In qualified mode, evidence provider authenticity MUST use qualified mechanisms as required by the applicable rules (REQ-D04).
- In non-qualified/dev mode, evidence may use non-qualified mechanisms but MUST be labeled and prevented from being represented as qualified (REQ-G02).

Non-obvious decision point (implementation detail): the precise signature container and certificate profiles to use (ETSI-aligned). This MUST be specified once the operator’s interoperability profile is chosen. (REQ-C04, REQ-D03)

## Trusted time

Evidence MUST include a trustworthy time reference (REQ-C03):

- The platform MUST define a time-source strategy (e.g., qualified timestamping authority integration, secure time synchronization, dual-source comparisons).
- Evidence verification MUST record how time trust was established.

## Key management and key lifecycle evidence

The platform MUST model evidence protection keys and their lifecycle (REQ-D04, REQ-H07):

- Key inventory with roles (evidence sealing key, audit-log chain key, etc.)
- Lifecycle events: generate, activate, rotate, revoke, retire
- Approvals / dual-control for sensitive lifecycle operations
- Exportable ceremony logs suitable for audit packs

In qualified mode, private keys used for qualified evidence MUST be generated/stored/used in an appropriately certified secure crypto device/module (QSCD/HSM as required). (REQ-D04)

