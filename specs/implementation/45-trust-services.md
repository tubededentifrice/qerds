# Trust services (self-hosted sealing + timestamping)

Covers: REQ-C02, REQ-C03, REQ-D03, REQ-D04, REQ-D08, REQ-G02, REQ-H07, REQ-H01

## Overview

`qerds-trust` is a dedicated internal service responsible for producing:

- provider attestation (seal/signature) over canonical evidence payloads, (REQ-C02)
- time attestation (timestamp token or equivalent), (REQ-C03)
- and verifiable key lifecycle ceremony evidence (metadata exports). (REQ-H07)

This is separated to enforce the cryptographic boundary. (REQ-D04)

## External standards / interfaces

- Timestamping SHOULD use RFC 3161 tokens unless an ETSI profile requires something else. (REQ-C03)
- Sealing/signing container format MUST be selected to align with ETSI EN 319 522 interoperability profile. (REQ-C04)

## Modes

### Non-qualified mode (default)

- Uses software keys (stored encrypted at rest).
- MUST label all outputs `qualification_label=non_qualified`. (REQ-G02)
- MUST be blocked from being enabled when `claim_state=qualified`. (REQ-G02)

### Qualified mode (restricted)

- No software keys; keys MUST be via PKCS#11 to certified crypto module/HSM, with operator-provided qualified credentials. (REQ-D04)
- MUST enforce “no fallback” policy: if HSM unavailable, fail closed. (REQ-D04)
- MUST record key id, device id, policy snapshot id into evidence bundles for audit. (REQ-H01, REQ-H07)

## Service APIs (internal)

All calls MUST be authenticated mutually (mTLS) and logged. (REQ-D08)

- `POST /trust/seal` → input: canonical bytes + metadata; output: attestation blob ref + cert chain refs
- `POST /trust/timestamp` → input: digest; output: timestamp token ref
- `POST /trust/checkpoint` → input: log stream checkpoint digest; output: sealed+timestamped checkpoint refs
- `GET /trust/keys` → key inventory metadata (no private material)
- `POST /trust/keys/{id}/rotate` → lifecycle operation requiring dual-control (policy) and ceremony logs (REQ-H07)

## Crypto agility

The platform MUST support:

- versioned algorithm suites (hash/signature),
- retaining verification material for historical suites,
- and producing clear audit evidence for suite changes. (REQ-D03, REQ-H05)

## Evidence bundling

For every signed/timestamped output, the trust service MUST produce a verification bundle containing:

- algorithm identifiers,
- signer certificate chain (public),
- timestamp policy identifiers,
- and policy snapshot references. (REQ-H01)

