# CPS Section 3: Identification and Authentication

**Document Status**: SKELETON
**Classification**: Published
**Covers**: REQ-B03, REQ-B05, REQ-F06

## 3.1 Naming

### 3.1.1 Types of Names

[TODO: Define naming conventions]

Parties are identified by:

- Legal name (for organizations)
- Full name (for individuals)
- Unique identifier (internal reference)
- [TODO: Other identifiers]

### 3.1.2 Need for Names to be Meaningful

Names MUST be meaningful and verifiable per REQ-B03.

### 3.1.3 Anonymity or Pseudonymity

[TODO: Define policy on anonymity/pseudonymity]

For LRE compliance, sender and recipient identification is MANDATORY. Anonymous or pseudonymous use is not permitted for qualified service.

## 3.2 Initial Identity Validation

### 3.2.1 Sender Identity Verification

**Covers**: REQ-B05

The provider MUST verify sender identity with a high level of confidence.

**Permitted verification methods**:

[TODO: Define specific methods based on REQ-B05]

- In-person identity document verification
- High-assurance eID (e.g., FranceConnect+)
- EUDI Wallet credentials
- Qualified certificates from trusted TSPs
- [TODO: Other assessed methods]

**Implementation**: See `specs/implementation/20-identities-and-roles.md` for identity verification levels.

### 3.2.2 Recipient Identification

**Covers**: REQ-B03

Recipients are identified through:

- Email address (for notification routing)
- Full identity verification at access time (e.g., FranceConnect+)

**Implementation**: See `specs/implementation/20-identities-and-roles.md` for recipient verification flow.

### 3.2.3 Consumer Consent (LRE)

**Covers**: REQ-F06

Where the recipient is a consumer, evidence of prior consent to receive LRE electronically MUST be retained.

[TODO: Define consent capture and retention procedures]

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for consent evidence requirements.

## 3.3 Identification and Authentication for Re-key

[TODO: Define re-key authentication if applicable]

For subscriber re-authentication:

- [TODO: Define requirements]

## 3.4 Identification and Authentication for Revocation

[TODO: Define revocation request authentication]

Revocation requests (where applicable) require:

- [TODO: Authentication requirements]

## 3.5 Authentication for Service Access

### 3.5.1 Sender Authentication

[TODO: Define sender authentication requirements]

Senders authenticate via:

- [TODO: Authentication methods]

### 3.5.2 Recipient Authentication

[TODO: Define recipient authentication requirements]

Recipients authenticate to claim content via:

- Strong authentication (e.g., FranceConnect+)
- [TODO: Other permitted methods]

### 3.5.3 Third-Party Verification

**Covers**: REQ-F01

Authorized third parties can verify evidence using:

- Public verification interface
- Verification identifier provided to recipient

**Implementation**: See `specs/implementation/60-interop-and-verification.md` for third-party verification.

## 3.6 Sender Identity Protection (LRE)

**Covers**: REQ-F03

Per CPCE requirements, the sender's identity MUST NOT be disclosed to the recipient before acceptance/refusal of the LRE.

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for pre-acceptance disclosure rules.

## Cross-References

- **Identities and Roles**: `specs/implementation/20-identities-and-roles.md`
- **Lifecycle and Evidence**: `specs/implementation/30-lifecycle-and-evidence.md`
- **Verification Interface**: `specs/implementation/60-interop-and-verification.md`
- **Privacy Policy**: `policies/privacy-policy.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
