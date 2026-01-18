# Open choices requiring operator/user confirmation

This file enumerates non-obvious decisions that materially affect interoperability, audits, and security posture.

## Interoperability (REQ-C04) — resolved

Selected:

1. Transport binding strategy: **AS4 via an existing gateway** AND **Standard Email (SMTP) via Pickup Portal**.
2. Concrete gateway (MSH): **Domibus**.
3. SMP/BDXR metadata publisher: **phoss SMP**.
4. Email transport: **In-scope**. Implemented as a notification + pickup portal flow (CPCE compliant).

## Confidentiality model (REQ-E01, REQ-H10) — resolved

Selected: **Operator-Managed Encryption**.

- Content is encrypted at rest (AES-GCM or similar) using keys managed by the platform (`qerds-trust`).
- The operator technically has the capability to decrypt (via the trust service), but access is restricted by policy and code to authorized sessions.
- Strict End-to-End Encryption (where operator has *no* key) is **not** the default, to allow for required features like virus scanning, format conversion, and evidence generation.

## Identity Verification Strategy (REQ-B05) — resolved

Selected: **Hybrid approach**.

1. **FranceConnect+ (Primary)**: Preferred for LRE compliance (IAL Substantial/High).
2. **Generic OIDC**: For foreign eIDAS nodes or other IdPs, with ACR mapping to internal IAL.
3. **Manual / Operator Verification**: Fallback "Registration Authority" workflow for users without supported eID.
