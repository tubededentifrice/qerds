# Open choices requiring operator/user confirmation

This file enumerates non-obvious decisions that materially affect interoperability, audits, and security posture.

## Interoperability (REQ-C04) — resolved defaults

Selected:

1. Transport binding strategy: **AS4 via an existing gateway**.

2. Concrete gateway (MSH): **Domibus**.

3. SMP/BDXR metadata publisher: **phoss SMP**.

Still open:

4. Confirm whether email/RFC5322 transport is in-scope as an additional binding (separate from inter-provider AS4).

## Confidentiality model (REQ-E01, REQ-H10)

Confirm whether the platform will support:

- strict end-to-end encryption (operator cannot decrypt) as the only mode, or
- optional operator-managed decrypt capability (with strict controls) for specific deployments.
