# ETSI interoperability profile (EN 319 522 / Implementing Regulation 2025/1944)

Covers: REQ-C04, REQ-B03, REQ-C01, REQ-C02, REQ-C03, REQ-E03, REQ-F01

## Objective

Define a single, versioned “interop profile” that:

- specifies which evidence format options are supported, (REQ-C04)
- defines which transport bindings are implemented (e.g., AS4), (REQ-C04)
- and defines verification/metadata publishing behaviors required for inter-provider interoperability.

## Selected approach (researched default)

Prioritize the **AS4 / eDelivery ecosystem** because it is broadly deployed in EU interoperability contexts and has mature self-hostable implementations.

Selected default profile (for this repo):

- Transport binding: **AS4** (EN 319 522-4-2 referenced family).
- Evidence packaging: ETSI-aligned canonicalization + signature container consistent with the selected EN 319 522 parts.
- Service metadata: **BDXR/SMP-style metadata** publication (EN 319 522-4-3 referenced family).

## Selected implementations (self-hosted)

### What “AS4” means here (explicit)

For this project, “AS4 support” means:

- We can exchange registered-delivery messages and evidence-related messages with other providers over an **AS4 Message Service Handler (MSH)**.
- We can receive/emit protocol receipts/errors and map them to our own `evidence_events` and evidence objects. (REQ-C01)
- We can publish/consume **service metadata** (SMP/BDXR) so other providers can route to us and validate our endpoints and certificates. (REQ-C04)

AS4 itself is a SOAP-based messaging profile; implementing it correctly (including security headers, retries, receipts) is complex and high-risk to build in-house.

### AS4 gateway (MSH): Domibus (selected)

- **Domibus** (Java, open source) is selected as the AS4 MSH.
- `qerds-api` integrates by pushing outbound messages to the gateway and consuming inbound messages/receipts from it, mapping them into:
  - delivery lifecycle transitions (where applicable),
  - `evidence_events`,
  - evidence sealing/timestamping workflows. (REQ-C01, REQ-C02, REQ-C03)

Why selected:

- Reduces protocol implementation scope in Python.
- Uses the European Commission’s **sample Access Point** software for the eDelivery AS4 profile, which is actively maintained and has dedicated conformance/connectivity testing support in the wider eDelivery ecosystem.
- License: EUPL 1.2 (audit/legal review friendly in EU public-sector contexts).

### SMP/BDXR metadata publisher: phoss SMP (selected)

- **phoss SMP** (Java, open source) is selected as the SMP/BDXR service metadata publisher.
- It supports **Peppol SMP 1.x** and **OASIS BDXR SMP 1.0/2.0**, and has a long-lived release history.
- It is advertised as the **first SMP to be CEF eDelivery conformant**.
- License: Apache 2.0 (per published artifacts).

### Alternatives considered (not selected by default)

- **Holodeck B2B**: open source AS4 MSH and “small & lightweight”, but GPLv3 licensing may complicate reuse/distribution decisions; keep as a fallback option if Domibus is rejected for operational reasons.

## Metadata publishing / trust establishment

To support inter-provider trust and routing:

- The platform MUST publish service metadata consistent with the chosen profile. (REQ-C04)
- The platform MUST be able to consume and validate relevant trust anchors (e.g., trusted lists / certificate constraints) to validate other providers. (REQ-C04, REQ-C02)

Implementation note (self-hosted constraint):

- These components MUST be deployable without relying on third-party hosted services.
- For development, containers may be built from upstream source.
- For production/audits, the build inputs MUST be pinned and reproducible (source pinned + SBOM captured into audit packs). (REQ-H01)

## Data minimisation

Interoperability payloads and verification endpoints MUST avoid leaking unnecessary PII; define redaction rules and “pre-acceptance” disclosure constraints where relevant. (REQ-E03, REQ-F03)
