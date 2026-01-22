# Certification Practice Statement (CPS)

**Document Status**: SKELETON
**Classification**: Published
**Covers**: REQ-A03

## Overview

This directory contains the Certification Practice Statement (CPS) for the QERDS/LRE service. The CPS describes the practices and procedures the provider employs to issue, manage, and operate trust services.

## Document Structure

The CPS follows the RFC 3647 framework adapted for ERDS, as recommended by ETSI EN 319 401 and EN 319 521:

| Section | Document | Description |
|---------|----------|-------------|
| 1 | [Introduction](01-introduction.md) | CPS scope, definitions, and contact information |
| 2 | [Publication and Repository](02-publication-repository.md) | How CPS and policies are published |
| 3 | [Identification and Authentication](03-identification-authentication.md) | How parties are identified and authenticated |
| 4 | [Certificate Lifecycle](04-certificate-lifecycle.md) | Seal/signature certificate management (where applicable) |
| 5 | [Facility Management](05-facility-management.md) | Physical and environmental security |
| 6 | [Technical Security](06-technical-security.md) | Technical security controls |
| 7 | [Profile](07-profile.md) | Evidence and certificate profiles |
| 8 | [Compliance and Audit](08-compliance-audit.md) | Conformity assessment and audit |
| 9 | [Other Matters](09-other-matters.md) | Legal, fees, and other provisions |

## Relationship to Other Policies

The CPS references and is supported by:

- [Security Policy](../security-policy.md) - Detailed security framework
- [Incident Policy](../incident-policy.md) - Incident handling procedures
- [Continuity Policy](../continuity-policy.md) - Business continuity
- [Key Management Policy](../key-management-policy.md) - Key lifecycle
- [Evidence Management Policy](../evidence-management-policy.md) - Evidence handling
- [Privacy Policy](../privacy-policy.md) - Data protection

## Publication

Per ETSI EN 319 401 and eIDAS requirements, this CPS (or a summary) MUST be published to relying parties. The publication location is defined in Section 2.

## Versioning

The CPS is versioned alongside the platform releases:

- Version numbers follow semantic versioning
- Each release tags the CPS version in effect
- Historical versions are available via git history

## Normative References

This CPS is aligned with:

- **RFC 3647** - Certificate Policy and Certification Practices Framework
- **ETSI EN 319 401** - General Policy Requirements for Trust Service Providers
- **ETSI EN 319 521** - Policy and Security Requirements for ERDS Providers
- **ETSI EN 319 522** - ERDS Evidence and Interoperability
- **Implementing Regulation (EU) 2025/1944** - eIDAS ERDS implementing rules

## Document History

| Version | Date | Author | Summary |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
