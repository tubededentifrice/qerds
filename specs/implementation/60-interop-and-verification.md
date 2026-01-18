# Interoperability and third-party verification

Covers: REQ-C04, REQ-E03, REQ-F01, REQ-F03, REQ-H10

## Interoperability profile boundary (ETSI EN 319 522)

The platform MUST implement evidence structures and interfaces aligned with the ETSI EN 319 522 parts required by Implementing Regulation (EU) 2025/1944, Annex II. (REQ-C04)

Because these standards may not be redistributable, this repository will:

- document an explicit “interop profile” (versioned) describing which EN 319 522 parts and which options are implemented,
- provide test vectors and conformance tests derived from permissible sources,
- provide validation tooling that checks produced evidence against the selected profile. (REQ-C04)

Non-obvious decision point: the exact profile/options and any national profile overlays. This requires the operator’s target interoperability ecosystem and access to the standards. (REQ-C04)

## Dual-Channel Transport (REQ-C04, REQ-F03)

The platform supports two delivery channels to maximize interoperability and compliance:

### 1. AS4 Gateway (QERDS Interop)
- **Protocol**: AS4 (eDelivery) via Domibus.
- **Use Case**: Delivery between Qualified Providers (e.g., QERDS-to-QERDS).
- **Binding**: ETSI EN 319 522-4-3 (AS4 binding).

### 2. Email + Web Pickup (LRE/Consumer)
- **Protocol**: Standard SMTP (Notification) + HTTPS (Pickup Portal).
- **Use Case**: Delivery to non-professional recipients (consumers) or recipients without an AS4 endpoint.
- **Compliance**: Implements the "Notification -> Authentication -> Acceptance -> Download" flow required by CPCE.

## Public verification surface (CPCE)

The platform MUST expose a verification function that allows authorized third parties to verify proofs using an identifier, as required by CPCE. (REQ-F01)

Specification requirements:

- Proofs MUST have a stable `proof_id` suitable for later verification.
- A **verification token** (high entropy) MUST be required in addition to `proof_id` unless an alternative legally accepted authorization exists (to minimize data exposure). (REQ-E03)
- Verification outputs MUST provide:
  - authenticity check result (signature/seal)
  - time trust check result
  - integrity checks (content hashes)
  - qualification label and basis reference (if any)
  - redacted identity fields pre-acceptance (REQ-F03)

## Pre-acceptance disclosure rules (Anonymity)

Any verification result or recipient portal API that can be accessed before acceptance/refusal MUST:

- **Strict Anonymity**: NOT disclose the sender's identity. (REQ-F03)
- **Content Protection**: NOT reveal the content itself.
- **Context Only**: Provide only what is necessary for the recipient to decide (provider identity, existence of a registered delivery, and legal framing). (REQ-E03)

For the **Email Notification**:
- The subject line and body MUST NOT contain the sender's name.
- It MUST contain a generic notice (e.g., "You have received a Registered Electronic Letter").
- The sender is revealed only *after* the recipient authenticates and clicks "Accept".
