# CPS Section 4: Certificate Lifecycle Management

**Document Status**: SKELETON
**Classification**: Published (summary), Internal (details)
**Covers**: REQ-D04, REQ-H07

## 4.1 Scope

This section covers the lifecycle management of:

- Provider seal certificates (used to seal evidence)
- Timestamp certificates (used for trusted time)
- Any other certificates used by the service

**Note**: The QERDS service itself does not issue end-user certificates. This section covers certificates used by the provider for service operation.

## 4.2 Certificate Application

### 4.2.1 Provider Certificates

[TODO: Define certificate application process]

Provider certificates (seal, timestamp) are obtained from:

- Qualified Trust Service Provider(s) for qualified mode
- Internal CA for non-qualified/dev mode (clearly labeled)

### 4.2.2 Certificate Profile Requirements

[TODO: Define certificate requirements]

Provider seal certificates MUST:

- Be issued by a qualified TSP (for qualified mode)
- Meet the profile requirements in Section 7
- Support the algorithms specified in `specs/implementation/40-evidence-crypto-and-time.md`

## 4.3 Certificate Application Processing

### 4.3.1 Performing Identification

[TODO: Define how provider identity is verified for certificate issuance]

### 4.3.2 Approval or Rejection

[TODO: Define approval process]

## 4.4 Certificate Issuance

### 4.4.1 Actions During Issuance

[TODO: Define issuance procedures]

Certificate issuance is performed as a key ceremony with:

- Multi-person control
- Documented procedures
- Evidence generation

**Implementation**: See `policies/key-management-policy.md` for ceremony requirements.

### 4.4.2 Notification

[TODO: Define notification procedures]

## 4.5 Certificate Acceptance

### 4.5.1 Acceptance Procedures

[TODO: Define acceptance criteria]

### 4.5.2 Publication

Provider seal certificate information is published per Section 2.

## 4.6 Key Pair and Certificate Usage

### 4.6.1 Private Key Protection

**Covers**: REQ-D04

Private keys MUST be:

- Generated within HSM/QSCD (qualified mode)
- Never exported in plaintext
- Used only for authorized purposes

**Implementation**: See `policies/key-management-policy.md` for key protection requirements.

### 4.6.2 Certificate Usage

Seal certificates are used to:

- Seal evidence objects
- Provide attribution to the provider

Timestamp certificates are used to:

- Provide trusted time references

## 4.7 Certificate Renewal

[TODO: Define renewal procedures]

### 4.7.1 Renewal Triggers

- Certificate approaching expiry
- Algorithm deprecation
- Key compromise (see revocation)

### 4.7.2 Renewal Process

[TODO: Define renewal process]

## 4.8 Certificate Re-key

[TODO: Define re-key procedures]

Re-keying follows the same procedures as initial key generation (Section 4.4).

## 4.9 Certificate Modification

[TODO: Define modification policy]

Certificate modification is not supported. A new certificate is issued instead.

## 4.10 Certificate Revocation

### 4.10.1 Revocation Triggers

[TODO: Define revocation triggers]

- Key compromise
- Certificate information changes
- Provider termination
- Regulatory requirement

### 4.10.2 Revocation Process

[TODO: Define revocation process]

### 4.10.3 Revocation Publication

Revocation status is published via:

- [TODO: CRL/OCSP location]

**Implementation**: Evidence verification includes revocation checking per `specs/implementation/60-interop-and-verification.md`.

## 4.11 Certificate Status Services

[TODO: Define status service availability]

Certificate status can be checked via:

- OCSP: [TODO: URL]
- CRL: [TODO: URL]

## 4.12 End of Subscription

[TODO: Define end of subscription procedures]

## 4.13 Key Escrow and Recovery

[TODO: Define escrow policy]

Key escrow is [permitted/not permitted] for:

- [TODO: Define scope]

**Implementation**: See `policies/key-management-policy.md` for key backup requirements.

## Cross-References

- **Key Management Policy**: `policies/key-management-policy.md`
- **Evidence Cryptography**: `specs/implementation/40-evidence-crypto-and-time.md`
- **Trust Services**: `specs/implementation/45-trust-services.md`
- **CPS Section 7 (Profiles)**: `policies/cps/07-profile.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
